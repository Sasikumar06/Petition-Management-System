// Petition List React Component
class PetitionsApp extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            petitions: [],
            loading: true,
            error: null,
            page: 1,
            totalPages: 1,
            filters: {
                status: '',
                priority: '',
                department: '',
                search: ''
            }
        };
    }

    componentDidMount() {
        this.loadPetitions();
    }

    loadPetitions = () => {
        const { page, filters } = this.state;
        const queryParams = new URLSearchParams();
        
        queryParams.append('page', page);
        if (filters.status) queryParams.append('status', filters.status);
        if (filters.priority) queryParams.append('priority', filters.priority);
        if (filters.department) queryParams.append('department', filters.department);
        if (filters.search) queryParams.append('search', filters.search);
        
        fetch(`/api/petitions?${queryParams.toString()}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to load petitions');
                }
                return response.json();
            })
            .then(data => {
                this.setState({
                    petitions: data.petitions,
                    loading: false,
                    totalPages: data.pages,
                    page: data.current_page
                });
            })
            .catch(error => {
                this.setState({
                    error: error.message,
                    loading: false
                });
            });
    }

    handlePageChange = (newPage) => {
        this.setState({ page: newPage, loading: true }, this.loadPetitions);
    }

    handleFilterChange = (e) => {
        const { name, value } = e.target;
        this.setState(prevState => ({
            filters: {
                ...prevState.filters,
                [name]: value
            },
            page: 1,
            loading: true
        }), this.loadPetitions);
    }

    handleSearchSubmit = (e) => {
        e.preventDefault();
        this.setState({ loading: true, page: 1 }, this.loadPetitions);
    }

    render() {
        const { petitions, loading, error, page, totalPages, filters } = this.state;

        if (loading) {
            return (
                <div className="text-center my-5">
                    <div className="spinner-border text-primary" role="status">
                        <span className="visually-hidden">Loading...</span>
                    </div>
                    <p className="mt-2">Loading petitions...</p>
                </div>
            );
        }

        if (error) {
            return (
                <div className="alert alert-danger my-3" role="alert">
                    <i className="fas fa-exclamation-triangle me-2"></i>
                    {error}
                </div>
            );
        }

        return (
            <div className="petitions-react-app">
                {/* Filter Form */}
                <div className="card mb-4">
                    <div className="card-header">
                        <i className="fas fa-filter me-1"></i>
                        Filter Petitions
                    </div>
                    <div className="card-body">
                        <form onSubmit={this.handleSearchSubmit}>
                            <div className="row g-3">
                                <div className="col-md-6">
                                    <input
                                        type="text"
                                        className="form-control"
                                        placeholder="Search petitions..."
                                        name="search"
                                        value={filters.search}
                                        onChange={this.handleFilterChange}
                                    />
                                </div>
                                <div className="col-md-2">
                                    <select
                                        className="form-select"
                                        name="status"
                                        value={filters.status}
                                        onChange={this.handleFilterChange}
                                    >
                                        <option value="">All Statuses</option>
                                        <option value="1">Pending</option>
                                        <option value="2">In Progress</option>
                                        <option value="3">Under Review</option>
                                        <option value="4">Awaiting Response</option>
                                        <option value="5">Resolved</option>
                                        <option value="6">Rejected</option>
                                    </select>
                                </div>
                                <div className="col-md-2">
                                    <select
                                        className="form-select"
                                        name="priority"
                                        value={filters.priority}
                                        onChange={this.handleFilterChange}
                                    >
                                        <option value="">All Priorities</option>
                                        <option value="High">High</option>
                                        <option value="Normal">Normal</option>
                                        <option value="Low">Low</option>
                                    </select>
                                </div>
                                <div className="col-md-2">
                                    <button type="submit" className="btn btn-primary w-100">
                                        <i className="fas fa-search me-1"></i>Search
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>

                {/* Petitions Grid */}
                <div className="row">
                    {petitions.length > 0 ? (
                        petitions.map(petition => (
                            <div className="col-lg-4 col-md-6 mb-4" key={petition.id}>
                                <div className="card petition-card h-100">
                                    <div className="card-header d-flex justify-content-between align-items-center">
                                        <span className={`status-badge status-${petition.status.toLowerCase().replace(' ', '-')}`}>
                                            {petition.status}
                                        </span>
                                        <span className={`status-badge priority-${petition.priority.toLowerCase()}`}>
                                            {petition.priority}
                                        </span>
                                    </div>
                                    <div className="card-body">
                                        <h5 className="card-title mb-3">{petition.title}</h5>
                                        <p className="card-text text-muted mb-2">
                                            <small><i className="fas fa-building me-1"></i>{petition.department}</small>
                                        </p>
                                        <p className="card-text text-muted mb-3">
                                            <small><i className="fas fa-clock me-1"></i>{petition.upload_date}</small>
                                        </p>
                                        {petition.tags && petition.tags.length > 0 && (
                                            <div className="tag-list">
                                                {petition.tags.map((tag, index) => (
                                                    <span className="tag" key={index}>{tag}</span>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                    <div className="card-footer bg-transparent">
                                        <a href={`/petition/${petition.id}`} className="btn btn-primary btn-sm w-100">
                                            <i className="fas fa-eye me-1"></i>View Details
                                        </a>
                                    </div>
                                </div>
                            </div>
                        ))
                    ) : (
                        <div className="col-12">
                            <div className="alert alert-info">
                                <i className="fas fa-info-circle me-2"></i>No petitions found matching your criteria.
                            </div>
                        </div>
                    )}
                </div>

                {/* Pagination */}
                {totalPages > 1 && (
                    <nav className="mt-4">
                        <ul className="pagination justify-content-center">
                            <li className={`page-item ${page === 1 ? 'disabled' : ''}`}>
                                <button
                                    className="page-link"
                                    onClick={() => this.handlePageChange(page - 1)}
                                    disabled={page === 1}
                                >
                                    <i className="fas fa-chevron-left"></i> Previous
                                </button>
                            </li>
                            
                            {Array.from({ length: totalPages }, (_, i) => i + 1).map(p => (
                                <li className={`page-item ${p === page ? 'active' : ''}`} key={p}>
                                    <button
                                        className="page-link"
                                        onClick={() => this.handlePageChange(p)}
                                    >
                                        {p}
                                    </button>
                                </li>
                            ))}
                            
                            <li className={`page-item ${page === totalPages ? 'disabled' : ''}`}>
                                <button
                                    className="page-link"
                                    onClick={() => this.handlePageChange(page + 1)}
                                    disabled={page === totalPages}
                                >
                                    Next <i className="fas fa-chevron-right"></i>
                                </button>
                            </li>
                        </ul>
                    </nav>
                )}
            </div>
        );
    }
}

// Initialize React component if container exists
document.addEventListener('DOMContentLoaded', function() {
    const container = document.getElementById('react-petitions-root');
    if (container) {
        ReactDOM.render(<PetitionsApp />, container);
    }
});