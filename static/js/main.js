document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });
    
    // Check for notifications every 60 seconds
    function checkNotifications() {
        fetch('/api/notifications/count')
            .then(response => response.json())
            .then(data => {
                const notifBadge = document.getElementById('notification-badge');
                if (notifBadge) {
                    if (data.count > 0) {
                        notifBadge.textContent = data.count;
                        notifBadge.style.display = 'inline';
                    } else {
                        notifBadge.style.display = 'none';
                    }
                }
            })
            .catch(err => console.error('Error checking notifications:', err));
    }
    
    // Initial check and set interval
    checkNotifications();
    setInterval(checkNotifications, 60000);
    
    // Live search functionality
    const searchInput = document.getElementById('search-input');
    const searchResults = document.getElementById('search-results');
    
    if (searchInput && searchResults) {
        let debounceTimer;
        
        searchInput.addEventListener('input', function() {
            clearTimeout(debounceTimer);
            
            const query = this.value.trim();
            if (query.length < 3) {
                searchResults.innerHTML = '';
                searchResults.style.display = 'none';
                return;
            }
            
            debounceTimer = setTimeout(() => {
                fetch(`/api/search?query=${encodeURIComponent(query)}`)
                    .then(response => response.json())
                    .then(data => {
                        searchResults.innerHTML = '';
                        
                        if (data.results.length === 0) {
                            searchResults.innerHTML = '<div class="search-result-item">No results found</div>';
                            searchResults.style.display = 'block';
                            return;
                        }
                        
                        data.results.forEach(result => {
                            const div = document.createElement('div');
                            div.className = 'search-result-item';
                            div.innerHTML = `
                                <div><strong>${result.title}</strong></div>
                                <div>Status: ${result.status} | Priority: ${result.priority}</div>
                                <div class="text-muted small">${result.date}</div>
                            `;
                            div.addEventListener('click', () => {
                                window.location.href = `/petition/${result.id}`;
                            });
                            searchResults.appendChild(div);
                        });
                        
                        searchResults.style.display = 'block';
                    })
                    .catch(err => console.error('Error searching:', err));
            }, 300);
        });
        
        // Hide search results when clicking outside
        document.addEventListener('click', function(event) {
            if (!searchInput.contains(event.target) && !searchResults.contains(event.target)) {
                searchResults.style.display = 'none';
            }
        });
    }
    
    // Charts initialization (if charts exist on page)
    const chartCanvas = document.getElementById('petitionChart');
    if (chartCanvas && typeof chartData !== 'undefined') {
        const ctx = chartCanvas.getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: chartData.map(item => item.month),
                datasets: [{
                    label: 'Petitions',
                    data: chartData.map(item => item.count),
                    backgroundColor: 'rgba(0, 123, 255, 0.2)',
                    borderColor: 'rgba(0, 123, 255, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    position: 'right',
                    labels: {
                      boxWidth: 12,
                      font: {
                        size: 10
                      }
                    }
                  }
                }
              }
        });
    }
});