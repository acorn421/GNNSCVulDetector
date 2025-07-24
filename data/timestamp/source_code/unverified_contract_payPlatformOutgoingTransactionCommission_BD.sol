/*
 * ===== SmartInject Injection Details =====
 * Function      : payPlatformOutgoingTransactionCommission
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability in the commission payment system. The vulnerability requires multiple transactions to exploit and involves:
 * 
 * 1. **State Accumulation**: Added persistent state variables (commissionAccumulationStart, accumulatedCommissionAmount, lastCommissionPaymentTime) that track commission timing across transactions
 * 
 * 2. **Time-Based Logic**: Implemented commission multipliers that increase based on time elapsed since accumulation started, using block.timestamp for critical calculations
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Initialize accumulation period during favorable timestamp
 *    - Transaction 2+: Accumulate commissions with time-based multipliers over multiple calls
 *    - Final Transaction: Trigger payout when accumulated amount is maximized
 * 
 * 4. **Timestamp Manipulation Vulnerabilities**:
 *    - Miners can manipulate block.timestamp to affect commission multiplier calculations
 *    - Time-based payout triggers can be gamed through timestamp manipulation
 *    - Commission accumulation periods can be exploited by controlling transaction timing
 * 
 * 5. **Realistic Attack Scenario**:
 *    - Attacker coordinates with miner to manipulate timestamps
 *    - Multiple transactions are used to accumulate commissions during favorable time windows
 *    - Final payout is triggered when accumulated commission is maximized through timing manipulation
 * 
 * The vulnerability is stateful (requires persistent state changes), multi-transaction (needs multiple calls to accumulate and exploit), and based on realistic timestamp dependence patterns seen in DeFi protocols.
 */
pragma solidity ^0.4.24;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that revert on error
 */
library SafeMath {

    /**
    * @dev Multiplies two numbers, reverts on overflow.
    */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b);

        return c;
    }

    /**
    * @dev Integer division of two numbers truncating the quotient, reverts on division by zero.
    */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0); // Solidity only automatically asserts when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
    * @dev Subtracts two numbers, reverts on overflow (i.e. if subtrahend is greater than minuend).
    */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        uint256 c = a - b;

        return c;
    }

    /**
    * @dev Adds two numbers, reverts on overflow.
    */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);

        return c;
    }

    /**
    * @dev Divides two numbers and returns the remainder (unsigned integer modulo),
    * reverts when dividing by zero.
    */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b != 0);
        return a % b;
    }
}

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
    address public owner;

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

}

/* Required code start */
contract MarketplaceProxy {
    function calculatePlatformCommission(uint256 weiAmount) public view returns (uint256);
    function payPlatformIncomingTransactionCommission(address clientAddress) public payable;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
// State variables to track commission timing (added to contract)
uint256 public commissionAccumulationStart;
uint256 public accumulatedCommissionAmount;
uint256 public lastCommissionPaymentTime;
uint256 constant COMMISSION_ACCUMULATION_PERIOD = 24 hours;
uint256 constant COMMISSION_MULTIPLIER_PERIOD = 1 hours;

function payPlatformOutgoingTransactionCommission() public payable {
    // Initialize accumulation period on first call
    if (commissionAccumulationStart == 0) {
        commissionAccumulationStart = block.timestamp;
        accumulatedCommissionAmount = msg.value;
        lastCommissionPaymentTime = block.timestamp;
        return;
    }
    
    // Calculate time-based commission multiplier
    uint256 timeElapsed = block.timestamp - commissionAccumulationStart;
    uint256 commissionMultiplier = 100; // Base 100% (1x)
    
    // Increase multiplier based on accumulation time
    if (timeElapsed >= COMMISSION_ACCUMULATION_PERIOD) {
        commissionMultiplier = 150; // 1.5x multiplier after 24 hours
    } else if (timeElapsed >= COMMISSION_MULTIPLIER_PERIOD) {
        // Vulnerable: Using block.timestamp for critical calculation
        // Miners can manipulate this for favorable timing
        commissionMultiplier = 100 + ((timeElapsed / COMMISSION_MULTIPLIER_PERIOD) * 10);
    }
    
    // Accumulate commission with time-based multiplier
    uint256 adjustedCommission = (msg.value * commissionMultiplier) / 100;
    accumulatedCommissionAmount += adjustedCommission;
    
    // Check if enough time has passed for payout (vulnerable to manipulation)
    uint256 timeSinceLastPayment = block.timestamp - lastCommissionPaymentTime;
    if (timeSinceLastPayment >= COMMISSION_ACCUMULATION_PERIOD) {
        // Reset accumulation period using manipulable timestamp
        commissionAccumulationStart = block.timestamp;
        
        // Pay out accumulated commission
        if (accumulatedCommissionAmount > 0) {
            address(this).transfer(accumulatedCommissionAmount);
            accumulatedCommissionAmount = 0;
        }
        
        lastCommissionPaymentTime = block.timestamp;
    }
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
}
    function isUserBlockedByContract(address contractAddress) public view returns (bool);
}
/* Required code end */

contract Deposit is Ownable {

    using SafeMath for uint256;

    struct ClientDeposit {
        uint256 balance;
        // We should reject incoming transactions on payable 
        // methods that not equals this variable
        uint256 nextPaymentTotalAmount;
        uint256 nextPaymentDepositCommission;   // deposit commission stored on contract
        uint256 nextPaymentPlatformCommission;
        bool exists;
        bool isBlocked;
    }
    mapping(address => ClientDeposit) public depositsMap;

    /* Required code start */
    MarketplaceProxy public mp;
    event PlatformIncomingTransactionCommission(uint256 amount, address indexed clientAddress);
    event PlatformOutgoingTransactionCommission(uint256 amount);
    event Blocked();
    /* Required code end */
    event MerchantIncomingTransactionCommission(uint256 amount, address indexed clientAddress);
    event DepositCommission(uint256 amount, address clientAddress);

    constructor () public {
        /* Required code start */
        // NOTE: CHANGE ADDRESS ON PRODUCTION
        mp = MarketplaceProxy(0x17b38d3779dEBcF1079506522E10284D3c6b0FEf);
        /* Required code end */
    }

    /**
     * @dev Handles direct clients transactions
     */
    function () public payable {
        handleIncomingPayment(msg.sender, msg.value);
    }

    /**
     * @dev Handles payment gateway transactions
     * @param clientAddress when payment method is fiat money
     */
    function fromPaymentGateway(address clientAddress) public payable {
        handleIncomingPayment(clientAddress, msg.value);
    }

    /**
     * @dev Send commission to marketplace and increases client balance
     * @param clientAddress client wallet for deposit
     * @param amount transaction value (msg.value)
     */
    function handleIncomingPayment(address clientAddress, uint256 amount) private {
        ClientDeposit storage clientDeposit = depositsMap[clientAddress];

        require(clientDeposit.exists);
        require(clientDeposit.nextPaymentTotalAmount == amount);

        /* Required code start */
        // Send all incoming eth if user blocked
        if (mp.isUserBlockedByContract(address(this))) {
            mp.payPlatformIncomingTransactionCommission.value(amount)(clientAddress);
            emit Blocked();
        } else {
            owner.transfer(clientDeposit.nextPaymentDepositCommission);
            emit MerchantIncomingTransactionCommission(clientDeposit.nextPaymentDepositCommission, clientAddress);
            mp.payPlatformIncomingTransactionCommission.value(clientDeposit.nextPaymentPlatformCommission)(clientAddress);
            emit PlatformIncomingTransactionCommission(clientDeposit.nextPaymentPlatformCommission, clientAddress);
        }
        /* Required code end */

        // Virtually add ETH to client deposit (sended ETH subtract platform and deposit commissions)
        clientDeposit.balance += amount.sub(clientDeposit.nextPaymentPlatformCommission).sub(clientDeposit.nextPaymentDepositCommission);
        emit DepositCommission(clientDeposit.nextPaymentDepositCommission, clientAddress);
    }

    /**
     * @dev Owner can add ETH to contract without commission
     */
    function addEth() public payable onlyOwner {

    }

    /**
     * @dev Send client's balance to some address on claim
     * @param from client address
     * @param to send ETH on this address
     * @param amount 18 decimals (wei)
     */
    function claim(address from, address to, uint256 amount) public onlyOwner{
        require(depositsMap[from].exists);

        /* Required code start */
        // Get commission amount from marketplace
        uint256 commission = mp.calculatePlatformCommission(amount);

        require(address(this).balance > amount.add(commission));
        require(depositsMap[from].balance >= amount);

        // Send commission to marketplace
        mp.payPlatformOutgoingTransactionCommission.value(commission)();
        emit PlatformOutgoingTransactionCommission(commission);
        /* Required code end */

        // Virtually subtract amount from client deposit
        depositsMap[from].balance -= amount;

        to.transfer(amount);
    }

    /**
     * @return bool, client exist or not
     */
    function isClient(address clientAddress) public view onlyOwner returns(bool) {
        return depositsMap[clientAddress].exists;
    }

    /**
     * @dev Add new client to structure
     * @param clientAddress wallet
     * @param _nextPaymentTotalAmount reject next incoming payable transaction if it's amount not equal to this variable
     * @param _nextPaymentDepositCommission deposit commission stored on contract
     * @param _nextPaymentPlatformCommission marketplace commission to send
     */
    function addClient(address clientAddress, uint256 _nextPaymentTotalAmount, uint256 _nextPaymentDepositCommission, uint256 _nextPaymentPlatformCommission) public onlyOwner {
        require( (clientAddress != address(0)));

        // Can be called only once for address
        require(!depositsMap[clientAddress].exists);

        // Add new element to structure
        depositsMap[clientAddress] = ClientDeposit(
            0,                                  // balance
            _nextPaymentTotalAmount,            // nextPaymentTotalAmount
            _nextPaymentDepositCommission,      // nextPaymentDepositCommission
            _nextPaymentPlatformCommission,     // nextPaymentPlatformCommission
            true,                               // exists
            false                               // isBlocked
        );
    }

    /**
     * @return uint256 client balance
     */
    function getClientBalance(address clientAddress) public view returns(uint256) {
        return depositsMap[clientAddress].balance;
    }

    /**
     * @dev Update client payment details
     * @param clientAddress wallet
     * @param _nextPaymentTotalAmount reject next incoming payable transaction if it's amount not equal to this variable
     * @param _nextPaymentDepositCommission deposit commission stored on contract
     * @param _nextPaymentPlatformCommission marketplace commission to send
     */
    function repeatedPayment(address clientAddress, uint256 _nextPaymentTotalAmount, uint256 _nextPaymentDepositCommission, uint256 _nextPaymentPlatformCommission) public onlyOwner {
        ClientDeposit storage clientDeposit = depositsMap[clientAddress];

        require(clientAddress != address(0));
        require(clientDeposit.exists);

        clientDeposit.nextPaymentTotalAmount = _nextPaymentTotalAmount;
        clientDeposit.nextPaymentDepositCommission = _nextPaymentDepositCommission;
        clientDeposit.nextPaymentPlatformCommission = _nextPaymentPlatformCommission;
    }
}