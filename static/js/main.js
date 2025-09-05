/**
 * Task Manager Pro - Main JavaScript File
 * Enhanced functionality for the task management system
 */

// =============================================================================
// GLOBAL VARIABLES AND CONFIGURATION
// =============================================================================

const CONFIG = {
    AUTO_SAVE_DELAY: 2000,
    NOTIFICATION_TIMEOUT: 5000,
    REFRESH_INTERVAL: 30000,
    MAX_SEARCH_RESULTS: 50
};

let autoSaveTimeout = null;
let refreshInterval = null;

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Show notification to user
 * @param {string} message - The message to display
 * @param {string} type - Type of notification (success, error, info, warning)
 * @param {number} duration - Duration in milliseconds
 */
function showNotification(message, type = 'info', duration = CONFIG.NOTIFICATION_TIMEOUT) {
    const container = document.getElementById('flash-container') || createNotificationContainer();
    
    const notification = document.createElement('div');
    notification.className = `flash-message flash-${type}`;
    
    const icon = getNotificationIcon(type);
    notification.innerHTML = `
        <i class="fas fa-${icon}"></i>
        <span>${message}</span>
        <button class="flash-close" onclick="closeFlash(this)">&times;</button>
    `;
    
    container.appendChild(notification);
    
    // Auto-remove after duration
    setTimeout(() => {
        if (notification.parentNode) {
            closeFlash(notification.querySelector('.flash-close'));
        }
    }, duration);
    
    // Add entrance animation
    setTimeout(() => notification.classList.add('show'), 10);
}

/**
 * Create notification container if it doesn't exist
 */
function createNotificationContainer() {
    const container = document.createElement('div');
    container.id = 'flash-container';
    document.body.appendChild(container);
    return container;
}

/**
 * Get appropriate icon for notification type
 */
function getNotificationIcon(type) {
    const icons = {
        success: 'check-circle',
        error: 'exclamation-triangle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };
    return icons[type] || 'info-circle';
}

/**
 * Close flash message
 */
function closeFlash(button) {
    const message = button.closest('.flash-message');
    message.style.opacity = '0';
    message.style.transform = 'translateX(100%)';
    setTimeout(() => {
        if (message.parentNode) {
            message.parentNode.removeChild(message);
        }
    }, 300);
}

/**
 * Debounce function to limit API calls
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Format date for display
 */
function formatDate(dateString) {
    if (!dateString) return '';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

/**
 * Format relative time (e.g., "2 hours ago")
 */
function formatRelativeTime(dateString) {
    if (!dateString) return '';
    const date = new Date(dateString);
    const now = new Date();
    const diffInSeconds = Math.floor((now - date) / 1000);
    
    if (diffInSeconds < 60) return 'Just now';
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
    if (diffInSeconds < 2592000) return `${Math.floor(diffInSeconds / 86400)} days ago`;
    
    return formatDate(dateString);
}

/**
 * Validate email format
 */
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Check if date is overdue
 */
function isOverdue(dateString) {
    if (!dateString) return false;
    const date = new Date(dateString);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    return date < today;
}

// =============================================================================
// PASSWORD UTILITIES
// =============================================================================

/**
 * Toggle password visibility
 */
function togglePassword(fieldId) {
    const field = document.getElementById(fieldId);
    const button = field.parentNode.querySelector('.password-toggle');
    const icon = button.querySelector('i');
    
    if (field.type === 'password') {
        field.type = 'text';
        icon.className = 'fas fa-eye-slash';
    } else {
        field.type = 'password';
        icon.className = 'fas fa-eye';
    }
}

/**
 * Check password strength
 */
function checkPasswordStrength(password) {
    const requirements = {
        length: password.length >= 8,
        upper: /[A-Z]/.test(password),
        lower: /[a-z]/.test(password),
        number: /\d/.test(password),
        special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
    };
    
    const score = Object.values(requirements).filter(Boolean).length;
    
    return {
        score,
        requirements,
        strength: ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'][score] || 'Very Weak'
    };
}

// =============================================================================
// FORM UTILITIES
// =============================================================================

/**
 * Auto-save form data
 */
function autoSaveForm(formId, endpoint) {
    const form = document.getElementById(formId);
    if (!form) return;
    
    const inputs = form.querySelectorAll('input, textarea, select');
    
    inputs.forEach(input => {
        input.addEventListener('input', debounce(() => {
            saveFormData(form, endpoint);
        }, CONFIG.AUTO_SAVE_DELAY));
    });
}

/**
 * Save form data to localStorage
 */
function saveFormData(form, key) {
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());
    
    try {
        localStorage.setItem(`autosave_${key}`, JSON.stringify(data));
    } catch (e) {
        console.warn('Could not save form data:', e);
    }
}

/**
 * Restore form data from localStorage
 */
function restoreFormData(formId, key) {
    try {
        const saved = localStorage.getItem(`autosave_${key}`);
        if (!saved) return;
        
        const data = JSON.parse(saved);
        const form = document.getElementById(formId);
        
        Object.keys(data).forEach(name => {
            const field = form.querySelector(`[name="${name}"]`);
            if (field && field.type !== 'hidden') {
                field.value = data[name];
            }
        });
        
        showNotification('Draft restored', 'info', 2000);
    } catch (e) {
        console.warn('Could not restore form data:', e);
    }
}

/**
 * Clear saved form data
 */
function clearSavedFormData(key) {
    try {
        localStorage.removeItem(`autosave_${key}`);
    } catch (e) {
        console.warn('Could not clear saved data:', e);
    }
}

// =============================================================================
// API UTILITIES
// =============================================================================

/**
 * Make API request with error handling
 */
async function apiRequest(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
        },
        credentials: 'same-origin'
    };
    
    const config = { ...defaultOptions, ...options };
    
    try {
        const response = await fetch(url, config);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return await response.json();
        }
        
        return await response.text();
    } catch (error) {
        console.error('API Request failed:', error);
        showNotification('Network error. Please try again.', 'error');
        throw error;
    }
}

/**
 * Update task status via API
 */
async function updateTaskStatusAPI(taskId, status) {
    try {
        const response = await apiRequest(`/api/tasks/${taskId}/status`, {
            method: 'PUT',
            body: JSON.stringify({ status })
        });
        
        if (response.success) {
            showNotification(`Task marked as ${status.replace('_', ' ')}`, 'success');
            return true;
        } else {
            showNotification('Failed to update task status', 'error');
            return false;
        }
    } catch (error) {
        return false;
    }
}

/**
 * Load tasks via API
 */
async function loadTasks(filters = {}) {
    try {
        const params = new URLSearchParams(filters);
        const response = await apiRequest(`/api/tasks?${params}`);
        
        if (response.success) {
            return response.tasks;
        } else {
            showNotification('Failed to load tasks', 'error');
            return [];
        }
    } catch (error) {
        return [];
    }
}

/**
 * Load statistics via API
 */
async function loadStats() {
    try {
        const response = await apiRequest('/api/stats');
        
        if (response.success) {
            return response.stats;
        } else {
            console.warn('Failed to load stats');
            return null;
        }
    } catch (error) {
        return null;
    }
}

// =============================================================================
// SEARCH AND FILTER FUNCTIONALITY
// =============================================================================

/**
 * Enhanced search functionality
 */
function setupAdvancedSearch() {
    const searchInput = document.getElementById('taskSearch');
    const statusFilter = document.getElementById('statusFilter');
    const priorityFilter = document.getElementById('priorityFilter');
    const categoryFilter = document.getElementById('categoryFilter');
    
    if (!searchInput) return;
    
    const debouncedSearch = debounce(performSearch, 300);
    
    searchInput.addEventListener('input', debouncedSearch);
    
    [statusFilter, priorityFilter, categoryFilter].forEach(filter => {
        if (filter) {
            filter.addEventListener('change', performSearch);
        }
    });
    
    // Enable keyboard navigation
    searchInput.addEventListener('keydown', handleSearchKeydown);
}

/**
 * Perform search with current filters
 */
function performSearch() {
    const searchTerm = document.getElementById('taskSearch')?.value.toLowerCase() || '';
    const statusFilter = document.getElementById('statusFilter')?.value || '';
    const priorityFilter = document.getElementById('priorityFilter')?.value || '';
    const categoryFilter = document.getElementById('categoryFilter')?.value || '';
    
    const tasks = document.querySelectorAll('.task-card');
    let visibleCount = 0;
    
    tasks.forEach(task => {
        const title = task.dataset.title || '';
        const description = task.dataset.description || '';
        const status = task.dataset.status || '';
        const priority = task.dataset.priority || '';
        const category = task.dataset.category || '';
        
        let show = true;
        
        // Text search
        if (searchTerm && !title.includes(searchTerm) && !description.includes(searchTerm)) {
            show = false;
        }
        
        // Status filter
        if (statusFilter && status !== statusFilter) {
            show = false;
        }
        
        // Priority filter
        if (priorityFilter && priority !== priorityFilter) {
            show = false;
        }
        
        // Category filter
        if (categoryFilter && category !== categoryFilter) {
            show = false;
        }
        
        task.style.display = show ? 'block' : 'none';
        if (show) visibleCount++;
    });
    
    updateSearchResults(visibleCount, tasks.length);
}

/**
 * Handle keyboard navigation in search
 */
function handleSearchKeydown(event) {
    if (event.key === 'Escape') {
        clearAllFilters();
    } else if (event.key === 'Enter') {
        event.preventDefault();
        // Focus first visible task
        const firstVisible = document.querySelector('.task-card[style*="block"], .task-card:not([style*="none"])');
        if (firstVisible) {
            firstVisible.scrollIntoView({ behavior: 'smooth', block: 'center' });
            firstVisible.classList.add('pulse');
            setTimeout(() => firstVisible.classList.remove('pulse'), 2000);
        }
    }
}

/**
 * Update search results display
 */
function updateSearchResults(visible, total) {
    const resultsInfo = document.getElementById('searchResults');
    if (resultsInfo) {
        resultsInfo.textContent = `Showing ${visible} of ${total} tasks`;
    }
}

/**
 * Clear all filters
 */
function clearAllFilters() {
    const filters = ['taskSearch', 'statusFilter', 'priorityFilter', 'categoryFilter'];
    
    filters.forEach(filterId => {
        const filter = document.getElementById(filterId);
        if (filter) {
            filter.value = '';
        }
    });
    
    // Show all tasks
    const tasks = document.querySelectorAll('.task-card');
    tasks.forEach(task => {
        task.style.display = 'block';
    });
    
    updateSearchResults(tasks.length, tasks.length);
    showNotification('Filters cleared', 'info', 2000);
}

// =============================================================================
// TASK MANAGEMENT
// =============================================================================

/**
 * Initialize task management functionality
 */
function initializeTaskManagement() {
    setupTaskActions();
    setupTaskModals();
    setupTaskDragAndDrop();
    setupTaskKeyboardShortcuts();
}

/**
 * Setup task action handlers
 */
function setupTaskActions() {
    document.addEventListener('click', (event) => {
        const target = event.target.closest('[data-action]');
        if (!target) return;
        
        const action = target.dataset.action;
        const taskId = target.dataset.taskId;
        
        switch (action) {
            case 'edit':
                openEditModal(taskId);
                break;
            case 'delete':
                confirmDeleteTask(taskId);
                break;
            case 'assign':
                openAssignModal(taskId);
                break;
            case 'toggle-status':
                toggleTaskStatus(taskId);
                break;
        }
    });
}

/**
 * Setup modal functionality
 */
function setupTaskModals() {
    // Close modals when clicking outside
    document.addEventListener('click', (event) => {
        if (event.target.classList.contains('modal')) {
            closeAllModals();
        }
    });
    
    // Close modals with Escape key
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            closeAllModals();
        }
    });
}

/**
 * Setup drag and drop for task reordering
 */
function setupTaskDragAndDrop() {
    const taskCards = document.querySelectorAll('.task-card');
    
    taskCards.forEach(card => {
        card.draggable = true;
        
        card.addEventListener('dragstart', (event) => {
            event.dataTransfer.setData('text/plain', card.dataset.taskId);
            card.classList.add('dragging');
        });
        
        card.addEventListener('dragend', () => {
            card.classList.remove('dragging');
        });
        
        card.addEventListener('dragover', (event) => {
            event.preventDefault();
        });
        
        card.addEventListener('drop', (event) => {
            event.preventDefault();
            const draggedId = event.dataTransfer.getData('text/plain');
            const draggedCard = document.querySelector(`[data-task-id="${draggedId}"]`);
            
            if (draggedCard && draggedCard !== card) {
                // Reorder cards
                const container = card.parentNode;
                const afterElement = getDragAfterElement(container, event.clientY);
                
                if (afterElement == null) {
                    container.appendChild(draggedCard);
                } else {
                    container.insertBefore(draggedCard, afterElement);
                }
                
                showNotification('Task order updated', 'success', 2000);
            }
        });
    });
}

/**
 * Get element to insert dragged item after
 */
function getDragAfterElement(container, y) {
    const draggableElements = [...container.querySelectorAll('.task-card:not(.dragging)')];
    
    return draggableElements.reduce((closest, child) => {
        const box = child.getBoundingClientRect();
        const offset = y - box.top - box.height / 2;
        
        if (offset < 0 && offset > closest.offset) {
            return { offset: offset, element: child };
        } else {
            return closest;
        }
    }, { offset: Number.NEGATIVE_INFINITY }).element;
}

/**
 * Setup keyboard shortcuts
 */
function setupTaskKeyboardShortcuts() {
    document.addEventListener('keydown', (event) => {
        // Only if not typing in an input
        if (event.target.tagName === 'INPUT' || event.target.tagName === 'TEXTAREA') {
            return;
        }
        
        if (event.ctrlKey || event.metaKey) {
            switch (event.key) {
                case 'n':
                    event.preventDefault();
                    openNewTaskModal();
                    break;
                case 'f':
                    event.preventDefault();
                    focusSearch();
                    break;
                case 's':
                    event.preventDefault();
                    saveCurrentTask();
                    break;
            }
        }
    });
}

/**
 * Focus search input
 */
function focusSearch() {
    const searchInput = document.getElementById('taskSearch');
    if (searchInput) {
        searchInput.focus();
        searchInput.select();
    }
}

/**
 * Close all open modals
 */
function closeAllModals() {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        modal.style.display = 'none';
    });
}

// =============================================================================
// REAL-TIME UPDATES
// =============================================================================

/**
 * Setup real-time updates
 */
function setupRealTimeUpdates() {
    // Refresh stats periodically
    refreshInterval = setInterval(refreshDashboardStats, CONFIG.REFRESH_INTERVAL);
    
    // Refresh when page becomes visible
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) {
            refreshDashboardStats();
        }
    });
    
    // Setup WebSocket connection for real-time updates (if available)
    setupWebSocket();
}

/**
 * Refresh dashboard statistics
 */
async function refreshDashboardStats() {
    const stats = await loadStats();
    if (stats) {
        updateStatsDisplay(stats);
    }
}

/**
 * Update statistics display
 */
function updateStatsDisplay(stats) {
    const statElements = {
        'total': stats.total_tasks,
        'pending': stats.pending_tasks,
        'progress': stats.in_progress_tasks,
        'completed': stats.completed_tasks,
        'overdue': stats.overdue_tasks,
        'completion': `${stats.completion_rate}%`
    };
    
    Object.entries(statElements).forEach(([type, value]) => {
        const element = document.querySelector(`.stat-card.${type} .stat-content h3`);
        if (element && element.textContent !== String(value)) {
            element.textContent = value;
            // Add update animation
            element.closest('.stat-card').classList.add('pulse');
            setTimeout(() => {
                element.closest('.stat-card').classList.remove('pulse');
            }, 1000);
        }
    });
}

/**
 * Setup WebSocket connection for real-time updates
 */
function setupWebSocket() {
    // This would connect to a WebSocket server for real-time updates
    // For now, we'll use polling instead
    console.log('WebSocket setup would go here for production');
}

// =============================================================================
// THEME AND PREFERENCES
// =============================================================================

/**
 * Setup theme switching
 */
function setupThemeToggle() {
    const themeToggle = document.getElementById('themeToggle');
    if (!themeToggle) return;
    
    const currentTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', currentTheme);
    
    themeToggle.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        showNotification(`Switched to ${newTheme} theme`, 'info', 2000);
    });
}

/**
 * Save user preferences
 */
function savePreferences(preferences) {
    try {
        localStorage.setItem('userPreferences', JSON.stringify(preferences));
    } catch (e) {
        console.warn('Could not save preferences:', e);
    }
}

/**
 * Load user preferences
 */
function loadPreferences() {
    try {
        const saved = localStorage.getItem('userPreferences');
        return saved ? JSON.parse(saved) : {};
    } catch (e) {
        console.warn('Could not load preferences:', e);
        return {};
    }
}

// =============================================================================
// ANALYTICS AND TRACKING
// =============================================================================

/**
 * Track user interaction
 */
function trackInteraction(action, details = {}) {
    // This would send analytics data to your tracking service
    console.log('Analytics:', { action, details, timestamp: new Date().toISOString() });
}

/**
 * Track page performance
 */
function trackPerformance() {
    if ('performance' in window) {
        window.addEventListener('load', () => {
            setTimeout(() => {
                const perfData = performance.timing;
                const loadTime = perfData.loadEventEnd - perfData.navigationStart;
                
                trackInteraction('page_load', {
                    loadTime,
                    userAgent: navigator.userAgent
                });
            }, 0);
        });
    }
}

// =============================================================================
// INITIALIZATION
// =============================================================================

/**
 * Initialize the application
 */
function initializeApp() {
    console.log('Initializing Task Manager Pro...');
    
    // Core functionality
    setupAdvancedSearch();
    initializeTaskManagement();
    setupRealTimeUpdates();
    
    // UI enhancements
    setupThemeToggle();
    setupAccessibilityFeatures();
    
    // Performance and analytics
    trackPerformance();
    
    // Auto-hide flash messages
    setupFlashMessages();
    
    // Setup form enhancements
    setupFormValidation();
    
    console.log('Task Manager Pro initialized successfully!');
}

/**
 * Setup accessibility features
 */
function setupAccessibilityFeatures() {
    // Add keyboard navigation indicators
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Tab') {
            document.body.classList.add('keyboard-nav');
        }
    });
    
    document.addEventListener('mousedown', () => {
        document.body.classList.remove('keyboard-nav');
    });
    
    // Setup screen reader announcements
    setupScreenReaderAnnouncements();
}

/**
 * Setup screen reader announcements
 */
function setupScreenReaderAnnouncements() {
    const announcer = document.createElement('div');
    announcer.setAttribute('aria-live', 'polite');
    announcer.setAttribute('aria-atomic', 'true');
    announcer.className = 'sr-only';
    announcer.id = 'screenReaderAnnouncer';
    document.body.appendChild(announcer);
}

/**
 * Announce message to screen readers
 */
function announceToScreenReader(message) {
    const announcer = document.getElementById('screenReaderAnnouncer');
    if (announcer) {
        announcer.textContent = message;
    }
}

/**
 * Setup flash message auto-hide
 */
function setupFlashMessages() {
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(message => {
        setTimeout(() => {
            if (message.parentNode) {
                closeFlash(message.querySelector('.flash-close'));
            }
        }, CONFIG.NOTIFICATION_TIMEOUT);
    });
}

/**
 * Setup form validation
 */
function setupFormValidation() {
    const forms = document.querySelectorAll('form[data-validate]');
    forms.forEach(form => {
        form.addEventListener('submit', validateForm);
    });
}

/**
 * Validate form before submission
 */
function validateForm(event) {
    const form = event.target;
    const requiredFields = form.querySelectorAll('[required]');
    let isValid = true;
    
    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            showFieldError(field, 'This field is required');
            isValid = false;
        } else {
            clearFieldError(field);
        }
    });
    
    // Email validation
    const emailFields = form.querySelectorAll('input[type="email"]');
    emailFields.forEach(field => {
        if (field.value && !validateEmail(field.value)) {
            showFieldError(field, 'Please enter a valid email address');
            isValid = false;
        }
    });
    
    if (!isValid) {
        event.preventDefault();
        announceToScreenReader('Please correct the errors in the form');
    }
}

/**
 * Show field error
 */
function showFieldError(field, message) {
    clearFieldError(field);
    
    field.classList.add('error');
    const errorElement = document.createElement('div');
    errorElement.className = 'field-error';
    errorElement.textContent = message;
    
    field.parentNode.appendChild(errorElement);
}

/**
 * Clear field error
 */
function clearFieldError(field) {
    field.classList.remove('error');
    const existingError = field.parentNode.querySelector('.field-error');
    if (existingError) {
        existingError.remove();
    }
}

// =============================================================================
// EVENT LISTENERS AND INITIALIZATION
// =============================================================================

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
} else {
    initializeApp();
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
    
    // Save any pending form data
    const activeForm = document.querySelector('form:focus-within');
    if (activeForm) {
        saveFormData(activeForm, 'emergency_save');
    }
});

// Handle online/offline status
window.addEventListener('online', () => {
    showNotification('Connection restored', 'success', 3000);
    refreshDashboardStats();
});

window.addEventListener('offline', () => {
    showNotification('You are offline. Some features may not work.', 'warning', 5000);
});

// Export functions for global use
window.TaskManager = {
    showNotification,
    togglePassword,
    closeFlash,
    clearAllFilters,
    updateTaskStatusAPI,
    loadTasks,
    trackInteraction,
    announceToScreenReader
};