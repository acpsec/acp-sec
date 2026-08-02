// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SentryAgent
 * @notice Reference AI agent contract demonstrating ERC-8183
 *         compliance patterns and ACP-SEC security best practices.
 *
 * @dev This is a minimal but production-grade reference implementation
 *      showcasing:
 *      - Job lifecycle management (Open → Funded → Submitted → Complete)
 *      - Evaluator role for third-party verification
 *      - Commitment immutability (prevents redirect attacks)
 *      - Reentrancy protection via checks-effects-interactions
 *      - Expiry recovery mechanism
 *      - Multi-chain ready
 *
 * @author SentryAgent — built for ACP-SEC ecosystem
 * @custom:security-contact security@acpsec.app
 */
contract SentryAgent {

    // ====================================================
    // AGENT IDENTITY (ACP-SEC AUTH dimension)
    // ====================================================

    string public constant AGENT_NAME = "SentryAgent";
    string public constant AGENT_VERSION = "1.0.0";
    string public constant AGENT_PURPOSE = "ERC-8183 reference implementation";
    address public immutable owner;

    // ====================================================
    // JOB LIFECYCLE (ERC-8183 compliance)
    // ====================================================

    enum JobStatus {
        Open,          // Job created
        Funded,        // Budget locked in escrow
        Submitted,     // Deliverable submitted
        Completed,     // Approved & paid
        Rejected,      // Rejected by evaluator
        Expired        // Past deadline
    }

    struct Job {
        address client;
        address provider;
        address evaluator;
        uint256 budget;
        uint256 expiredAt;
        bytes32 deliverable;
        JobStatus status;
        bool fundsReleased;  // Commitment immutability flag
    }

    mapping(uint256 => Job) public jobs;
    uint256 public nextJobId;

    // ====================================================
    // EVENTS (transparency & on-chain audit log)
    // ====================================================

    event JobCreated(uint256 indexed jobId, address client, address provider, uint256 budget);
    event JobFunded(uint256 indexed jobId, uint256 amount);
    event JobSubmitted(uint256 indexed jobId, bytes32 deliverable);
    event JobCompleted(uint256 indexed jobId);
    event JobRejected(uint256 indexed jobId, string reason);
    event FundsRecovered(uint256 indexed jobId, address recipient);

    // ====================================================
    // ERRORS (gas-efficient revert messages)
    // ====================================================

    error NotAuthorized();
    error InvalidJobStatus();
    error InsufficientFunds();
    error JobNotExpired();
    error AlreadyReleased();
    error ZeroAddress();
    error InvalidExpiry();

    // ====================================================
    // MODIFIERS (access control)
    // ====================================================

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotAuthorized();
        _;
    }

    modifier onlyEvaluator(uint256 jobId) {
        if (msg.sender != jobs[jobId].evaluator) revert NotAuthorized();
        _;
    }

    // ====================================================
    // CONSTRUCTOR
    // ====================================================

    constructor() {
        owner = msg.sender;
    }

    // ====================================================
    // JOB LIFECYCLE FUNCTIONS
    // ====================================================

    /**
     * @notice Create a new job (ERC-8183 lifecycle: Open)
     * @param provider Address of the agent that will execute the job
     * @param evaluator Independent third-party verifier
     * @param expiredAt Unix timestamp for job expiry
     */
    function createJob(
        address provider,
        address evaluator,
        uint256 expiredAt
    ) external returns (uint256 jobId) {
        if (provider == address(0)) revert ZeroAddress();
        if (evaluator == address(0)) revert ZeroAddress();
        if (expiredAt <= block.timestamp) revert InvalidExpiry();

        jobId = nextJobId++;

        jobs[jobId] = Job({
            client: msg.sender,
            provider: provider,
            evaluator: evaluator,
            budget: 0,
            expiredAt: expiredAt,
            deliverable: bytes32(0),
            status: JobStatus.Open,
            fundsReleased: false
        });

        emit JobCreated(jobId, msg.sender, provider, 0);
    }

    /**
     * @notice Fund the job with ETH (escrow)
     * @dev Checks-effects-interactions pattern for reentrancy safety
     */
    function fundJob(uint256 jobId) external payable {
        Job storage job = jobs[jobId];

        // Checks
        if (job.status != JobStatus.Open) revert InvalidJobStatus();
        if (job.client != msg.sender) revert NotAuthorized();
        if (msg.value == 0) revert InsufficientFunds();

        // Effects (commitment immutability — budget cannot be changed after funding)
        job.budget = msg.value;
        job.status = JobStatus.Funded;

        emit JobFunded(jobId, msg.value);
    }

    /**
     * @notice Provider submits deliverable
     * @param deliverable IPFS hash or content hash of the work output
     */
    function submitDeliverable(uint256 jobId, bytes32 deliverable) external {
        Job storage job = jobs[jobId];

        if (job.status != JobStatus.Funded) revert InvalidJobStatus();
        if (job.provider != msg.sender) revert NotAuthorized();

        job.deliverable = deliverable;
        job.status = JobStatus.Submitted;

        emit JobSubmitted(jobId, deliverable);
    }

    /**
     * @notice Evaluator approves the job, releases funds to provider
     * @dev Reentrancy-safe via checks-effects-interactions + fundsReleased flag
     */
    function completeJob(uint256 jobId) external onlyEvaluator(jobId) {
        Job storage job = jobs[jobId];

        // Checks
        if (job.status != JobStatus.Submitted) revert InvalidJobStatus();
        if (job.fundsReleased) revert AlreadyReleased();

        // Effects (state change BEFORE external call)
        job.status = JobStatus.Completed;
        job.fundsReleased = true;
        uint256 payment = job.budget;

        emit JobCompleted(jobId);

        // Interactions (external call LAST)
        (bool success, ) = job.provider.call{value: payment}("");
        if (!success) revert InsufficientFunds();
    }

    /**
     * @notice Evaluator rejects the job, refunds client
     */
    function rejectJob(uint256 jobId, string calldata reason) external onlyEvaluator(jobId) {
        Job storage job = jobs[jobId];

        // Checks
        if (job.status != JobStatus.Submitted) revert InvalidJobStatus();
        if (job.fundsReleased) revert AlreadyReleased();

        // Effects
        job.status = JobStatus.Rejected;
        job.fundsReleased = true;
        uint256 refund = job.budget;

        emit JobRejected(jobId, reason);

        // Interactions
        (bool success, ) = job.client.call{value: refund}("");
        if (!success) revert InsufficientFunds();
    }

    /**
     * @notice Recovery mechanism for expired jobs
     * @dev Pattern inspired by ariessa's FundTransferHook.recoverTokens
     */
    function recoverExpiredJob(uint256 jobId) external {
        Job storage job = jobs[jobId];

        // Checks
        if (block.timestamp < job.expiredAt) revert JobNotExpired();
        if (job.fundsReleased) revert AlreadyReleased();
        if (job.status != JobStatus.Funded && job.status != JobStatus.Submitted) {
            revert InvalidJobStatus();
        }

        // Effects
        job.status = JobStatus.Expired;
        job.fundsReleased = true;
        uint256 refund = job.budget;
        address recipient = job.client;

        emit FundsRecovered(jobId, recipient);

        // Interactions
        (bool success, ) = recipient.call{value: refund}("");
        if (!success) revert InsufficientFunds();
    }

    // ====================================================
    // VIEW FUNCTIONS (transparency)
    // ====================================================

    function getJob(uint256 jobId) external view returns (Job memory) {
        return jobs[jobId];
    }

    function getAgentInfo() external pure returns (
        string memory name,
        string memory version,
        string memory purpose
    ) {
        return (AGENT_NAME, AGENT_VERSION, AGENT_PURPOSE);
    }
}
