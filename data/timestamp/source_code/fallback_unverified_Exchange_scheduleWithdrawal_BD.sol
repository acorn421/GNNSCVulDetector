/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a stateful timestamp dependence vulnerability in a withdrawal scheduling system. The vulnerability requires multiple transactions to exploit: first calling scheduleWithdrawal() to set up the withdrawal state, then calling executeScheduledWithdrawal() to execute it. The vulnerability lies in the use of 'now' (block.timestamp) which can be manipulated by miners within certain bounds. The state (scheduledWithdrawals and withdrawalTimestamps mappings) persists between transactions, making this a multi-transaction stateful vulnerability. A malicious miner could potentially manipulate timestamps to bypass the intended delay period.
 */
pragma solidity ^0.4.24;

contract Ownable {
    address public owner;

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    /**
     * @dev The Ownable constructor sets the original `owner` of the contract to the sender
     * account.
     */
    constructor() public {
        owner = msg.sender;
    }
    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    /**
    * @dev Allows the current owner to transfer control of the contract to a newOwner.
    * @param newOwner The address to transfer ownership to.
    */
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

contract Erc20 {
    function balanceOf(address _owner) public view returns (uint256);
    function transfer(address _to, uint256 _value) public returns (bool);
    function approve(address _spender, uint256 _value) public returns (bool);
}

contract Exchange {
    function ethToTokenSwapInput(uint256 min_tokens, uint256 deadline)
        public
        payable
        returns (uint256);
}

contract LendingPool {
    function deposit( address _reserve, uint256 _amount, uint16 _referralCode) external payable;
}

contract aDaiGateway is Ownable {
    Exchange constant DaiEx = Exchange(0x2a1530C4C41db0B0b2bB646CB5Eb1A67b7158667);
    LendingPool constant lendingPool = LendingPool(0x398eC7346DcD622eDc5ae82352F02bE94C62d119);

    Erc20 constant  dai = Erc20(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    Erc20 constant aDai = Erc20(0xfC1E690f61EFd961294b3e1Ce3313fBD8aa4f85d);

    uint16 constant referral = 47;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for scheduled withdrawals
    mapping(address => uint256) public scheduledWithdrawals;
    mapping(address => uint256) public withdrawalTimestamps;
    uint256 public constant WITHDRAWAL_DELAY = 24 hours;
    // === END FALLBACK INJECTION ===

    constructor() public {
        dai.approve(0x3dfd23A6c5E8BbcFc9581d2E864a68feb6a076d3, uint256(-1)); //lendingPoolCore
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    /**
     * @dev Schedule a withdrawal that can be executed after a delay
     * @param amount The amount to withdraw
     */
    function scheduleWithdrawal(uint256 amount) public {
        require(amount > 0, "Amount must be greater than 0");
        require(aDai.balanceOf(msg.sender) >= amount, "Insufficient aDai balance");
        scheduledWithdrawals[msg.sender] += amount;
        withdrawalTimestamps[msg.sender] = now + WITHDRAWAL_DELAY;
    }
    /**
     * @dev Execute a scheduled withdrawal if delay has passed
     */
    function executeScheduledWithdrawal() public {
        uint256 amount = scheduledWithdrawals[msg.sender];
        require(amount > 0, "No scheduled withdrawal");
        require(now >= withdrawalTimestamps[msg.sender], "Withdrawal delay not met");
        scheduledWithdrawals[msg.sender] = 0;
        withdrawalTimestamps[msg.sender] = 0;
        aDai.transfer(msg.sender, amount);
    }
    // === END FALLBACK INJECTION ===

    function() external payable {
        etherToaDai(msg.sender);
    }

    function etherToaDai(address to)
        public
        payable
        returns (uint256 outAmount)
    {
        uint256 amount = DaiEx.ethToTokenSwapInput.value(
            (msg.value * 995) / 1000
        )(1, now);
        lendingPool.deposit(address(dai), amount, referral);
        outAmount = aDai.balanceOf(address(this));
        aDai.transfer(to, outAmount);
    }

    function makeprofit() public {
        owner.transfer(address(this).balance);
    }

}
