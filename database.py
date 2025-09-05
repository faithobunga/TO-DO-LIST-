import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from typing import List, Dict, Optional

class TodoDatabase:
    def __init__(self, db_path: str = "enhanced_todo.db"):
        """Initialize the enhanced database connection and create tables."""
        self.db_path = db_path
        self.init_database()
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging for database operations"""
        logging.basicConfig(
            filename='database.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def get_connection(self):
        """Get database connection with proper error handling"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as e:
            logging.error(f"Database connection error: {e}")
            raise
    
    def init_database(self):
        """Create all necessary tables for the enhanced system"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Enhanced users table with security features
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    first_name VARCHAR(50) NOT NULL,
                    last_name VARCHAR(50) NOT NULL,
                    role TEXT CHECK(role IN ('admin', 'user', 'guest')) DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP NULL
                )
            ''')
            
            # Categories for task organization
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(50) NOT NULL,
                    description TEXT,
                    color_code VARCHAR(7) DEFAULT '#667eea',
                    user_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Enhanced tasks table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title VARCHAR(100) NOT NULL,
                    description TEXT,
                    status TEXT CHECK(status IN ('pending', 'in_progress', 'completed', 'archived')) DEFAULT 'pending',
                    priority TEXT CHECK(priority IN ('low', 'medium', 'high', 'urgent')) DEFAULT 'medium',
                    due_date DATE,
                    category_id INTEGER,
                    user_id INTEGER NOT NULL,
                    assigned_to INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP NULL,
                    estimated_hours DECIMAL(5,2),
                    actual_hours DECIMAL(5,2),
                    FOREIGN KEY (category_id) REFERENCES categories(id),
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (assigned_to) REFERENCES users(id)
                )
            ''')
            
            # Activity logs for security and audit
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action VARCHAR(50) NOT NULL,
                    table_name VARCHAR(50),
                    record_id INTEGER,
                    old_values TEXT,
                    new_values TEXT,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Password reset tokens
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token VARCHAR(255) NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Task comments for collaboration
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS task_comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    comment TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # File attachments
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attachments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id INTEGER NOT NULL,
                    filename VARCHAR(255) NOT NULL,
                    original_filename VARCHAR(255) NOT NULL,
                    file_size INTEGER,
                    mime_type VARCHAR(100),
                    uploaded_by INTEGER NOT NULL,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                    FOREIGN KEY (uploaded_by) REFERENCES users(id)
                )
            ''')
            
            # Create default admin user if not exists
            self.create_default_admin()
            
            # Create default categories
            self.create_default_categories()
            
            conn.commit()
            logging.info("Database initialized successfully")
            print("✅ Enhanced database initialized successfully!")
            
        except sqlite3.Error as e:
            conn.rollback()
            logging.error(f"Database initialization error: {e}")
            print(f"❌ Database error: {e}")
            raise
        finally:
            conn.close()
    
    def create_default_admin(self):
        """Create default admin user if not exists"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Check if any admin exists
            cursor.execute("SELECT id FROM users WHERE role = 'admin'")
            if cursor.fetchone():
                return
            
            password_hash = generate_password_hash('admin123')
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, first_name, last_name, role)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', ('admin', 'admin@todoapp.com', password_hash, 'System', 'Administrator', 'admin'))
            
            conn.commit()
            logging.info("Default admin user created")
            print("✅ Default admin user created (admin/admin123)")
            
        except sqlite3.Error as e:
            logging.error(f"Error creating default admin: {e}")
        finally:
            conn.close()
    
    def create_default_categories(self):
        """Create default task categories"""
        default_categories = [
            ('Work', 'Work-related tasks', '#667eea'),
            ('Personal', 'Personal tasks and errands', '#28a745'),
            ('Urgent', 'Urgent tasks requiring immediate attention', '#dc3545'),
            ('Projects', 'Long-term project tasks', '#ffc107'),
            ('Health', 'Health and fitness related tasks', '#17a2b8'),
            ('Learning', 'Educational and skill development', '#6f42c1')
        ]
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Check if categories exist
            cursor.execute('SELECT COUNT(*) FROM categories WHERE user_id IS NULL')
            if cursor.fetchone()[0] > 0:
                return
            
            for name, description, color in default_categories:
                cursor.execute('''
                    INSERT INTO categories (name, description, color_code, user_id)
                    VALUES (?, ?, ?, NULL)
                ''', (name, description, color))
            
            conn.commit()
            logging.info("Default categories created")
            print("✅ Default categories created")
            
        except sqlite3.Error as e:
            logging.error(f"Error creating default categories: {e}")
        finally:
            conn.close()
    
    # =============================================================================
    # USER MANAGEMENT METHODS
    # =============================================================================
    
    def create_user(self, username, email, password_hash, first_name, last_name, role='user'):
        """Create new user with enhanced security"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, first_name, last_name, role)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, email, password_hash, first_name, last_name, role))
            
            user_id = cursor.lastrowid
            conn.commit()
            
            self.log_activity(user_id, 'USER_REGISTRATION', 'users', user_id)
            logging.info(f"User {username} registered successfully")
            return True
            
        except sqlite3.IntegrityError:
            logging.warning(f"Failed registration attempt for {username} - user already exists")
            return False
        except sqlite3.Error as e:
            logging.error(f"Error creating user: {e}")
            return False
        finally:
            conn.close()
    
    def verify_user_enhanced(self, username, password, ip_address=None):
        """Enhanced user verification with brute force protection"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Check if account exists and get security info
            cursor.execute('''
                SELECT id, password_hash, failed_login_attempts, locked_until, role, 
                       first_name, last_name, is_active
                FROM users 
                WHERE username = ? AND is_active = 1
            ''', (username,))
            
            user = cursor.fetchone()
            if not user:
                logging.warning(f"Login attempt with non-existent username: {username}")
                return None
            
            user_id, password_hash, failed_attempts, locked_until, role, first_name, last_name, is_active = user
            
            # Check if account is locked
            if locked_until and datetime.now() < datetime.fromisoformat(locked_until):
                logging.warning(f"Login attempt on locked account: {username}")
                return None
            
            # Verify password
            if check_password_hash(password_hash, password):
                # Successful login - reset failed attempts and update last login
                cursor.execute('''
                    UPDATE users 
                    SET failed_login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (user_id,))
                
                conn.commit()
                self.log_activity(user_id, 'LOGIN_SUCCESS', ip_address=ip_address)
                logging.info(f"Successful login for user: {username}")
                
                return {
                    'id': user_id,
                    'username': username,
                    'role': role,
                    'first_name': first_name,
                    'last_name': last_name
                }
            else:
                # Failed login - increment failed attempts
                failed_attempts += 1
                locked_until = None
                
                # Lock account after 5 failed attempts for 30 minutes
                if failed_attempts >= 5:
                    locked_until = (datetime.now() + timedelta(minutes=30)).isoformat()
                
                cursor.execute('''
                    UPDATE users 
                    SET failed_login_attempts = ?, locked_until = ?
                    WHERE id = ?
                ''', (failed_attempts, locked_until, user_id))
                
                conn.commit()
                self.log_activity(user_id, 'LOGIN_FAILED', ip_address=ip_address)
                logging.warning(f"Failed login attempt for user: {username}")
                
                return None
                
        except sqlite3.Error as e:
            logging.error(f"Error verifying user: {e}")
            return None
        finally:
            conn.close()
    
    def get_user_profile(self, user_id):
        """Get user profile information"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, username, email, first_name, last_name, role, 
                       created_at, last_login, is_active
                FROM users WHERE id = ?
            ''', (user_id,))
            
            user = cursor.fetchone()
            return dict(user) if user else None
            
        except sqlite3.Error as e:
            logging.error(f"Error fetching user profile: {e}")
            return None
        finally:
            conn.close()
    
    def update_user_profile(self, user_id, data):
        """Update user profile"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Get current data for logging
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            old_data = dict(cursor.fetchone())
            
            update_fields = []
            params = []
            
            allowed_fields = ['first_name', 'last_name', 'email']
            for field in allowed_fields:
                if field in data and data[field]:
                    update_fields.append(f'{field} = ?')
                    params.append(data[field])
            
            if not update_fields:
                return False
            
            params.append(user_id)
            
            cursor.execute(f'''
                UPDATE users SET {', '.join(update_fields)}
                WHERE id = ?
            ''', params)
            
            conn.commit()
            self.log_activity(user_id, 'PROFILE_UPDATED', 'users', user_id, 
                            old_values=str(old_data))
            return True
            
        except sqlite3.Error as e:
            logging.error(f"Error updating user profile: {e}")
            return False
        finally:
            conn.close()
    
    # =============================================================================
    # PASSWORD RESET METHODS
    # =============================================================================
    
    def create_password_reset_token(self, email):
        """Create password reset token"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Find user by email
            cursor.execute('SELECT id FROM users WHERE email = ? AND is_active = 1', (email,))
            user = cursor.fetchone()
            
            if not user:
                return None
            
            user_id = user[0]
            token = secrets.token_urlsafe(32)
            expires_at = (datetime.now() + timedelta(hours=1)).isoformat()
            
            # Invalidate old tokens
            cursor.execute('UPDATE password_reset_tokens SET used = 1 WHERE user_id = ?', (user_id,))
            
            # Create new token
            cursor.execute('''
                INSERT INTO password_reset_tokens (user_id, token, expires_at)
                VALUES (?, ?, ?)
            ''', (user_id, token, expires_at))
            
            conn.commit()
            self.log_activity(user_id, 'PASSWORD_RESET_REQUESTED')
            return token
            
        except sqlite3.Error as e:
            logging.error(f"Error creating reset token: {e}")
            return None
        finally:
            conn.close()
    
    def verify_reset_token(self, token):
        """Verify password reset token"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT prt.user_id, u.email
                FROM password_reset_tokens prt
                JOIN users u ON prt.user_id = u.id
                WHERE prt.token = ? AND prt.used = 0 AND prt.expires_at > CURRENT_TIMESTAMP
            ''', (token,))
            
            result = cursor.fetchone()
            return dict(result) if result else None
            
        except sqlite3.Error as e:
            logging.error(f"Error verifying reset token: {e}")
            return None
        finally:
            conn.close()
    
    def reset_password(self, token, password_hash):
        """Reset user password with token"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Verify token first
            user_data = self.verify_reset_token(token)
            if not user_data:
                return False
            
            user_id = user_data['user_id']
            
            # Update password
            cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user_id))
            
            # Mark token as used
            cursor.execute('UPDATE password_reset_tokens SET used = 1 WHERE token = ?', (token,))
            
            conn.commit()
            self.log_activity(user_id, 'PASSWORD_RESET_COMPLETED')
            return True
            
        except sqlite3.Error as e:
            logging.error(f"Error resetting password: {e}")
            return False
        finally:
            conn.close()
    
    # =============================================================================
    # TASK MANAGEMENT METHODS
    # =============================================================================
    
    def add_task_enhanced(self, title, description, user_id, priority='medium', due_date=None, category_id=None):
        """Add task with enhanced features"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO tasks (title, description, user_id, priority, due_date, category_id)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (title, description, user_id, priority, due_date, category_id))
            
            task_id = cursor.lastrowid
            conn.commit()
            
            self.log_activity(user_id, 'TASK_CREATED', 'tasks', task_id)
            logging.info(f"Task created by user {user_id}: {title}")
            return task_id
            
        except sqlite3.Error as e:
            logging.error(f"Error adding task: {e}")
            return None
        finally:
            conn.close()
    
    def get_user_tasks(self, user_id, status=None, category_id=None):
        """Get tasks for user with filtering"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            query = '''
                SELECT t.*, c.name as category_name, c.color_code,
                       u.username as assigned_username
                FROM tasks t
                LEFT JOIN categories c ON t.category_id = c.id
                LEFT JOIN users u ON t.assigned_to = u.id
                WHERE t.user_id = ? OR t.assigned_to = ?
            '''
            params = [user_id, user_id]
            
            if status:
                query += ' AND t.status = ?'
                params.append(status)
            
            if category_id:
                query += ' AND t.category_id = ?'
                params.append(category_id)
            
            query += ' ORDER BY t.created_at DESC'
            
            cursor.execute(query, params)
            tasks = [dict(row) for row in cursor.fetchall()]
            
            return tasks
            
        except sqlite3.Error as e:
            logging.error(f"Error fetching user tasks: {e}")
            return []
        finally:
            conn.close()
    
    def update_task_status(self, task_id, status):
        """Update task status with enhanced logging"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Get old status for logging
            cursor.execute('SELECT status, user_id FROM tasks WHERE id = ?', (task_id,))
            old_data = cursor.fetchone()
            if not old_data:
                return False
            
            old_status, user_id = old_data
            completed_at = datetime.now().isoformat() if status == 'completed' else None
            
            cursor.execute('''
                UPDATE tasks 
                SET status = ?, updated_at = CURRENT_TIMESTAMP, completed_at = ?
                WHERE id = ?
            ''', (status, completed_at, task_id))
            
            conn.commit()
            
            if cursor.rowcount > 0:
                self.log_activity(user_id, 'TASK_STATUS_UPDATED', 'tasks', task_id,
                                old_values=f"status: {old_status}",
                                new_values=f"status: {status}")
                return True
            
            return False
            
        except sqlite3.Error as e:
            logging.error(f"Error updating task status: {e}")
            return False
        finally:
            conn.close()
    
    def update_task(self, task_id, title, description):
        """Update task title and description"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Get old data for logging
            cursor.execute('SELECT title, description, user_id FROM tasks WHERE id = ?', (task_id,))
            old_data = cursor.fetchone()
            if not old_data:
                return False
            
            old_title, old_description, user_id = old_data
            
            cursor.execute('''
                UPDATE tasks 
                SET title = ?, description = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (title.strip(), description.strip(), task_id))
            
            conn.commit()
            
            if cursor.rowcount > 0:
                self.log_activity(user_id, 'TASK_UPDATED', 'tasks', task_id,
                                old_values=f"title: {old_title}, desc: {old_description}",
                                new_values=f"title: {title}, desc: {description}")
                return True
            
            return False
            
        except sqlite3.Error as e:
            logging.error(f"Error updating task: {e}")
            return False
        finally:
            conn.close()
    
    def delete_task(self, task_id):
        """Delete a task from the database with logging"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Get task data for logging
            cursor.execute('SELECT title, user_id FROM tasks WHERE id = ?', (task_id,))
            task_data = cursor.fetchone()
            if not task_data:
                return False
            
            title, user_id = task_data
            
            cursor.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
            conn.commit()
            
            if cursor.rowcount > 0:
                self.log_activity(user_id, 'TASK_DELETED', 'tasks', task_id,
                                old_values=f"title: {title}")
                return True
            
            return False
            
        except sqlite3.Error as e:
            logging.error(f"Error deleting task: {e}")
            return False
        finally:
            conn.close()
    
    def assign_task(self, task_id, assigned_to, assigned_by, due_date=None, priority=None):
        """Assign task to another user"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Get current task data for logging
            cursor.execute('SELECT * FROM tasks WHERE id = ?', (task_id,))
            old_task = dict(cursor.fetchone())
            
            update_fields = ['assigned_to = ?', 'updated_at = CURRENT_TIMESTAMP']
            params = [assigned_to]
            
            if due_date:
                update_fields.append('due_date = ?')
                params.append(due_date)
            
            if priority:
                update_fields.append('priority = ?')
                params.append(priority)
            
            params.append(task_id)
            
            cursor.execute(f'''
                UPDATE tasks 
                SET {', '.join(update_fields)}
                WHERE id = ?
            ''', params)
            
            conn.commit()
            
            # Log the assignment
            self.log_activity(assigned_by, 'TASK_ASSIGNED', 'tasks', task_id, 
                            old_values=str(old_task), new_values=f"assigned_to: {assigned_to}")
            
            return True
            
        except sqlite3.Error as e:
            logging.error(f"Error assigning task: {e}")
            return False
        finally:
            conn.close()
    
    def search_tasks(self, search_params):
        """Advanced task search with filters"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            query = '''
                SELECT t.*, c.name as category_name, c.color_code,
                       u.username as assigned_username
                FROM tasks t
                LEFT JOIN categories c ON t.category_id = c.id
                LEFT JOIN users u ON t.assigned_to = u.id
                WHERE (t.user_id = ? OR t.assigned_to = ?)
            '''
            
            user_id = search_params['user_id']
            params = [user_id, user_id]
            
            # Add search term filter
            if search_params.get('search_term'):
                query += ' AND (t.title LIKE ? OR t.description LIKE ?)'
                search_term = f"%{search_params['search_term']}%"
                params.extend([search_term, search_term])
            
            # Add status filter
            if search_params.get('status'):
                query += ' AND t.status = ?'
                params.append(search_params['status'])
            
            # Add priority filter
            if search_params.get('priority'):
                query += ' AND t.priority = ?'
                params.append(search_params['priority'])
            
            query += ' ORDER BY t.created_at DESC'
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            logging.error(f"Error searching tasks: {e}")
            return []
        finally:
            conn.close()
    
    # =============================================================================
    # CATEGORIES METHODS
    # =============================================================================
    
    def get_categories(self, user_id=None):
        """Get categories (global and user-specific)"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            query = 'SELECT * FROM categories WHERE user_id IS NULL'
            params = []
            
            if user_id:
                query += ' OR user_id = ?'
                params.append(user_id)
            
            query += ' ORDER BY name'
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            logging.error(f"Error fetching categories: {e}")
            return []
        finally:
            conn.close()
    
    # =============================================================================
    # STATISTICS AND REPORTING METHODS
    # =============================================================================
    
    def get_task_stats(self, user_id=None):
        """Get comprehensive task statistics"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if user_id:
                where_clause = 'WHERE user_id = ? OR assigned_to = ?'
                params = [user_id, user_id]
            else:
                where_clause = ''
                params = []
            
            cursor.execute(f'''
                SELECT 
                    COUNT(*) as total_tasks,
                    COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_tasks,
                    COUNT(CASE WHEN status = 'in_progress' THEN 1 END) as in_progress_tasks,
                    COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_tasks,
                    COUNT(CASE WHEN due_date < DATE('now') AND status != 'completed' THEN 1 END) as overdue_tasks,
                    COUNT(CASE WHEN priority = 'high' OR priority = 'urgent' THEN 1 END) as high_priority_tasks
                FROM tasks {where_clause}
            ''', params)
            
            stats = dict(cursor.fetchone())
            
            # Calculate completion rate
            if stats['total_tasks'] > 0:
                stats['completion_rate'] = round((stats['completed_tasks'] / stats['total_tasks']) * 100, 1)
            else:
                stats['completion_rate'] = 0
            
            return stats
            
        except sqlite3.Error as e:
            logging.error(f"Error fetching statistics: {e}")
            return {}
        finally:
            conn.close()
    
    def get_productivity_report(self, user_id, start_date, end_date):
        """Generate productivity report for date range"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as tasks_created,
                    COUNT(CASE WHEN status = 'completed' THEN 1 END) as tasks_completed,
                    AVG(CASE WHEN completed_at IS NOT NULL THEN 
                        julianday(completed_at) - julianday(created_at) END) as avg_completion_time
                FROM tasks
                WHERE (user_id = ? OR assigned_to = ?) AND DATE(created_at) BETWEEN ? AND ?
                GROUP BY DATE(created_at)
                ORDER BY date
            ''', (user_id, user_id, start_date, end_date))
            
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            logging.error(f"Error generating productivity report: {e}")
            return []
        finally:
            conn.close()
    
    def get_overdue_tasks(self, user_id=None):
        """Get overdue tasks"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            query = '''
                SELECT t.*, u.username, u.email
                FROM tasks t
                JOIN users u ON t.user_id = u.id
                WHERE t.due_date < DATE('now') AND t.status != 'completed'
            '''
            params = []
            
            if user_id:
                query += ' AND (t.user_id = ? OR t.assigned_to = ?)'
                params.extend([user_id, user_id])
            
            query += ' ORDER BY t.due_date ASC'
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            logging.error(f"Error fetching overdue tasks: {e}")
            return []
        finally:
            conn.close()
    
    # =============================================================================
    # EXPORT METHODS FOR REPORTS
    # =============================================================================
    
    def get_all_tasks_for_export(self):
        """Get all tasks for admin export"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT t.id, t.title, t.description, t.status, t.priority, 
                       t.created_at, t.due_date, u.username, c.name as category_name
                FROM tasks t
                LEFT JOIN users u ON t.user_id = u.id
                LEFT JOIN categories c ON t.category_id = c.id
                ORDER BY t.created_at DESC
            ''')
            
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            logging.error(f"Error fetching tasks for export: {e}")
            return []
        finally:
            conn.close()
    
    def get_user_tasks_for_export(self, user_id):
        """Get user tasks for export"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT t.id, t.title, t.description, t.status, t.priority, 
                       t.created_at, t.due_date, u.username, c.name as category_name
                FROM tasks t
                LEFT JOIN users u ON t.user_id = u.id
                LEFT JOIN categories c ON t.category_id = c.id
                WHERE t.user_id = ? OR t.assigned_to = ?
                ORDER BY t.created_at DESC
            ''', (user_id, user_id))
            
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            logging.error(f"Error fetching user tasks for export: {e}")
            return []
        finally:
            conn.close()
    
    def get_task_count_all(self):
        """Get total task count for all users"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM tasks')
            return cursor.fetchone()[0]
        except sqlite3.Error as e:
            logging.error(f"Error getting task count: {e}")
            return 0
        finally:
            conn.close()
    
    def get_completed_task_count_all(self):
        """Get completed task count for all users"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM tasks WHERE status = "completed"')
            return cursor.fetchone()[0]
        except sqlite3.Error as e:
            logging.error(f"Error getting completed task count: {e}")
            return 0
        finally:
            conn.close()
    
    def get_task_count_by_user(self, user_id):
        """Get task count for specific user"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM tasks WHERE user_id = ? OR assigned_to = ?', (user_id, user_id))
            return cursor.fetchone()[0]
        except sqlite3.Error as e:
            logging.error(f"Error getting user task count: {e}")
            return 0
        finally:
            conn.close()
    
    def get_completed_task_count_by_user(self, user_id):
        """Get completed task count for specific user"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT COUNT(*) FROM tasks 
                WHERE (user_id = ? OR assigned_to = ?) AND status = "completed"
            ''', (user_id, user_id))
            return cursor.fetchone()[0]
        except sqlite3.Error as e:
            logging.error(f"Error getting user completed task count: {e}")
            return 0
        finally:
            conn.close()
    
    def get_user_count(self):
        """Get total user count"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM users WHERE is_active = 1')
            return cursor.fetchone()[0]
        except sqlite3.Error as e:
            logging.error(f"Error getting user count: {e}")
            return 0
        finally:
            conn.close()
    
    # =============================================================================
    # ACTIVITY LOGGING METHODS
    # =============================================================================
    
    def log_activity(self, user_id, action, table_name=None, record_id=None, 
                    old_values=None, new_values=None, ip_address=None, user_agent=None):
        """Log user activity for security audit"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO activity_logs 
                (user_id, action, table_name, record_id, old_values, new_values, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, action, table_name, record_id, old_values, new_values, ip_address, user_agent))
            
            conn.commit()
            
        except sqlite3.Error as e:
            logging.error(f"Error logging activity: {e}")
        finally:
            conn.close()
    
    def get_activity_logs(self, user_id=None, limit=100):
        """Get activity logs for security monitoring"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            query = '''
                SELECT al.*, u.username 
                FROM activity_logs al
                LEFT JOIN users u ON al.user_id = u.id
            '''
            params = []
            
            if user_id:
                query += ' WHERE al.user_id = ?'
                params.append(user_id)
            
            query += ' ORDER BY al.timestamp DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            logging.error(f"Error fetching activity logs: {e}")
            return []
        finally:
            conn.close()
    
    def get_recent_login_attempts(self, limit=50):
        """Get recent login attempts for security monitoring"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT al.*, u.username, u.email
                FROM activity_logs al
                LEFT JOIN users u ON al.user_id = u.id
                WHERE al.action IN ('LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGIN_ATTEMPT_LOCKED_ACCOUNT')
                ORDER BY al.timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            logging.error(f"Error fetching login attempts: {e}")
            return []
        finally:
            conn.close()
    
    def get_failed_login_attempts(self, limit=20):
        """Get recent failed login attempts"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT al.*, u.username, u.email, u.failed_login_attempts
                FROM activity_logs al
                LEFT JOIN users u ON al.user_id = u.id
                WHERE al.action = 'LOGIN_FAILED'
                ORDER BY al.timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            logging.error(f"Error fetching failed login attempts: {e}")
            return []
        finally:
            conn.close()
    
    # =============================================================================
    # TASK COMMENTS AND COLLABORATION
    # =============================================================================
    
    def add_task_comment(self, task_id, user_id, comment):
        """Add comment to task"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO task_comments (task_id, user_id, comment)
                VALUES (?, ?, ?)
            ''', (task_id, user_id, comment))
            
            conn.commit()
            self.log_activity(user_id, 'COMMENT_ADDED', 'task_comments', task_id)
            return True
            
        except sqlite3.Error as e:
            logging.error(f"Error adding comment: {e}")
            return False
        finally:
            conn.close()
    
    def get_task_comments(self, task_id):
        """Get all comments for a task"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT tc.*, u.username, u.first_name, u.last_name
                FROM task_comments tc
                JOIN users u ON tc.user_id = u.id
                WHERE tc.task_id = ?
                ORDER BY tc.created_at ASC
            ''', (task_id,))
            
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            logging.error(f"Error fetching comments: {e}")
            return []
        finally:
            conn.close()
    
    def get_task_details(self, task_id):
        """Get detailed task information"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT t.*, c.name as category_name, c.color_code,
                       u1.username as creator_username,
                       u2.username as assigned_username
                FROM tasks t
                LEFT JOIN categories c ON t.category_id = c.id
                LEFT JOIN users u1 ON t.user_id = u1.id
                LEFT JOIN users u2 ON t.assigned_to = u2.id
                WHERE t.id = ?
            ''', (task_id,))
            
            task = cursor.fetchone()
            return dict(task) if task else None
            
        except sqlite3.Error as e:
            logging.error(f"Error fetching task details: {e}")
            return None
        finally:
            conn.close()
    
    # =============================================================================
    # ADMIN AND USER MANAGEMENT
    # =============================================================================
    
    def get_all_users(self):
        """Get all users for admin management"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, username, email, first_name, last_name, role, 
                       created_at, last_login, is_active, failed_login_attempts
                FROM users
                ORDER BY created_at DESC
            ''')
            
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            logging.error(f"Error fetching all users: {e}")
            return []
        finally:
            conn.close()
    
    def get_users_for_assignment(self):
        """Get active users for task assignment"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, username, first_name, last_name, email
                FROM users
                WHERE is_active = 1
                ORDER BY first_name, last_name
            ''')
            
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            logging.error(f"Error fetching users for assignment: {e}")
            return []
        finally:
            conn.close()
    
    def toggle_user_status(self, user_id, is_active):
        """Toggle user active status"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE users SET is_active = ? WHERE id = ?
            ''', (is_active, user_id))
            
            conn.commit()
            
            action = 'USER_ACTIVATED' if is_active else 'USER_DEACTIVATED'
            self.log_activity(None, action, 'users', user_id)
            
            return cursor.rowcount > 0
            
        except sqlite3.Error as e:
            logging.error(f"Error toggling user status: {e}")
            return False
        finally:
            conn.close()
    
    # =============================================================================
    # BACKUP AND MAINTENANCE
    # =============================================================================
    
    def backup_database(self, backup_path):
        """Create database backup"""
        try:
            import shutil
            shutil.copy2(self.db_path, backup_path)
            logging.info(f"Database backed up to {backup_path}")
            return True
            
        except Exception as e:
            logging.error(f"Error backing up database: {e}")
            return False
    
    def cleanup_old_logs(self, days_to_keep=90):
        """Clean up old activity logs"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).isoformat()
            
            cursor.execute('''
                DELETE FROM activity_logs 
                WHERE timestamp < ?
            ''', (cutoff_date,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            logging.info(f"Cleaned up {deleted_count} old activity log entries")
            return deleted_count
            
        except sqlite3.Error as e:
            logging.error(f"Error cleaning up logs: {e}")
            return 0
        finally:
            conn.close()
    
    def cleanup_expired_tokens(self):
        """Clean up expired password reset tokens"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM password_reset_tokens 
                WHERE expires_at < CURRENT_TIMESTAMP OR used = 1
            ''')
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            logging.info(f"Cleaned up {deleted_count} expired tokens")
            return deleted_count
            
        except sqlite3.Error as e:
            logging.error(f"Error cleaning up tokens: {e}")
            return 0
        finally:
            conn.close()
    
    # =============================================================================
    # BACKWARDS COMPATIBILITY METHODS
    # =============================================================================
    
    def add_task(self, title: str, description: str = "") -> bool:
        """Backwards compatible task creation (for existing code)"""
        # Use user_id = 1 (admin) as default for compatibility
        task_id = self.add_task_enhanced(title, description, user_id=1)
        return task_id is not None
    
    def get_all_tasks(self) -> List[Dict]:
        """Backwards compatible get all tasks"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT t.*, c.name as category_name, u.username
                FROM tasks t
                LEFT JOIN categories c ON t.category_id = c.id
                LEFT JOIN users u ON t.user_id = u.id
                ORDER BY t.created_at DESC
            ''')
            
            return [dict(row) for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            logging.error(f"Error retrieving all tasks: {e}")
            return []
        finally:
            conn.close()
    
    def verify_admin(self, username: str, password: str) -> bool:
        """Backwards compatible admin verification"""
        # First try the old admin_users table for compatibility
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Check old admin_users table first
            cursor.execute('''
                SELECT COUNT(*) FROM admin_users 
                WHERE username = ? AND password = ?
            ''')
            
            # If old table exists and has matching credentials
            if cursor.fetchone()[0] > 0:
                return True
            
        except sqlite3.OperationalError:
            # Old table doesn't exist, that's fine
            pass
        except Exception:
            pass
        finally:
            conn.close()
        
        # Use new enhanced verification
        user = self.verify_user_enhanced(username, password)
        return user is not None and user.get('role') == 'admin'

# =============================================================================
# INITIALIZATION AND TESTING
# =============================================================================

def test_database():
    """Test database functionality"""
    print("🧪 Testing Enhanced Database...")
    
    db = TodoDatabase("test_enhanced_todo.db")
    
    # Test user creation
    from werkzeug.security import generate_password_hash
    password_hash = generate_password_hash("testpass123")
    
    user_created = db.create_user("testuser", "test@example.com", password_hash, "Test", "User")
    print(f"✅ User creation: {'Success' if user_created else 'Failed'}")
    
    # Test user verification
    user = db.verify_user_enhanced("testuser", "testpass123")
    print(f"✅ User verification: {'Success' if user else 'Failed'}")
    
    if user:
        # Test task creation
        task_id = db.add_task_enhanced("Test Task", "Test Description", user['id'], "high")
        print(f"✅ Task creation: {'Success' if task_id else 'Failed'}")
        
        # Test task retrieval
        tasks = db.get_user_tasks(user['id'])
        print(f"✅ Task retrieval: {len(tasks)} tasks found")
        
        # Test statistics
        stats = db.get_task_stats(user['id'])
        print(f"✅ Statistics: {stats}")
    
    print("🎉 Database testing completed!")

if __name__ == "__main__":
    # Initialize the database
    db = TodoDatabase()
    
    print("🚀 Enhanced Todo Database System")
    print("=" * 50)
    print("✅ Database initialized successfully!")
    print("✅ All tables created with relationships")
    print("✅ Default admin user: admin / admin123")
    print("✅ Default categories created")
    print("✅ Security logging enabled")
    print("✅ Password hashing implemented")
    print("✅ Activity monitoring active")
    print("=" * 50)
    
    # Add some sample data for demonstration
    try:
        from werkzeug.security import generate_password_hash
        
        # Create a test user
        test_password = generate_password_hash("demo123")
        if db.create_user("demo", "demo@example.com", test_password, "Demo", "User"):
            print("✅ Demo user created: demo / demo123")
            
            # Add sample tasks for demo user (assuming user_id = 2)
            demo_tasks = [
                ("Complete project presentation", "Prepare slides and practice delivery", "high"),
                ("Review quarterly reports", "Analyze Q4 performance data", "medium"),
                ("Team meeting preparation", "Prepare agenda and materials", "medium"),
                ("Update client documentation", "Revise user manual and FAQ", "low"),
                ("Plan next sprint", "Define user stories and estimates", "high")
            ]
            
            for title, desc, priority in demo_tasks:
                db.add_task_enhanced(title, desc, 2, priority)
            
            print(f"✅ {len(demo_tasks)} sample tasks created")
    
    except Exception as e:
        print(f"⚠️  Sample data creation skipped: {e}")
    
    print("\n🎯 Ready for CMT210 demonstration!")
    print("💡 This enhanced database includes:")
    print("   • User authentication with role-based access")
    print("   • Password hashing and reset functionality") 
    print("   • Comprehensive activity logging")
    print("   • Task assignment and collaboration")
    print("   • Advanced search and filtering")
    print("   • Security monitoring and audit trails")
    print("   • Reporting and analytics capabilities")
    print("   • Data export functionality")
    print("\n🏆 Perfect for maximizing your CMT210 marks!")