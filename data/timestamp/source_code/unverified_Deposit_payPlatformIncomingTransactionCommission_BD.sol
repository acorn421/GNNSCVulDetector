/*
 * ===== SmartInject Injection Details =====
 * Function      : payPlatformIncomingTransactionCommission
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based commission rate calculation. The vulnerability allows attackers to manipulate commission rates by exploiting block.timestamp dependencies across multiple transactions.
 * 
 * **Key Changes Made:**
 * 
 * 1. **State Variables Added:**
 *    - `clientLastPaymentTime`: Maps client addresses to their last payment timestamp
 *    - `clientPaymentCount`: Tracks consecutive payments within loyalty period
 *    - `baseCommissionRate`, `loyaltyDiscountPeriod`, `maxLoyaltyDiscount`: Configuration for time-based logic
 * 
 * 2. **Timestamp-Dependent Logic:**
 *    - Commission rate calculation based on `block.timestamp`
 *    - Loyalty discount system that depends on time elapsed between payments
 *    - Payment count resets if too much time passes between transactions
 * 
 * 3. **Multi-Transaction State Accumulation:**
 *    - Each transaction updates payment timestamp and count
 *    - Commission rates depend on historical payment patterns
 *    - State persists between transactions to enable exploitation
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * 1. **Miner Timestamp Manipulation:**
 *    - Transaction 1: Client makes initial payment, establishing baseline timestamp
 *    - Transaction 2: Miner manipulates block.timestamp to appear within loyalty period
 *    - Transaction 3+: Continued payments with artificially reduced commission rates
 *    - Exploitation requires coordination across multiple blocks/transactions
 * 
 * 2. **Loyalty Period Gaming:**
 *    - Transaction 1: Initial payment sets `clientLastPaymentTime`
 *    - Transaction 2: Wait for favorable timestamp conditions, then make payment just within loyalty period
 *    - Transaction 3+: Rapid successive payments to accumulate loyalty discount
 *    - Each transaction builds on previous state to achieve maximum discount
 * 
 * 3. **Temporal Arbitrage:**
 *    - Attacker monitors block timestamps and times payments strategically
 *    - Multiple transactions needed to build up payment count while staying within loyalty period
 *    - Exploitation requires sequence of transactions with specific timing
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Accumulation:** The vulnerability depends on `clientPaymentCount` building up over multiple transactions
 * 2. **Temporal Dependencies:** Each payment's commission depends on the timestamp of the previous payment
 * 3. **Historical Context:** The discount system requires establishing payment history across multiple transactions
 * 4. **Time Window Exploitation:** Manipulating the loyalty period requires coordinated timing across multiple blocks
 * 
 * **Realistic Attack Vector:**
 * A sophisticated attacker or miner could manipulate block.timestamp (within the ~900 second tolerance) to:
 * - Extend loyalty periods artificially
 * - Accumulate payment counts while maintaining "consecutive" timing
 * - Reduce commission rates significantly through timestamp manipulation
 * - Coordinate multiple transactions to maximize discount exploitation
 * 
 * This creates a genuine, exploitable timestamp dependence vulnerability that requires stateful, multi-transaction exploitation while maintaining the function's core commission payment functionality.
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Add state variables to track time-based commission rates
    mapping(address => uint256) public clientLastPaymentTime;
    mapping(address => uint256) public clientPaymentCount;
    uint256 public baseCommissionRate = 100; // 1% in basis points
    uint256 public loyaltyDiscountPeriod = 300; // 5 minutes in seconds
    uint256 public maxLoyaltyDiscount = 50; // 0.5% maximum discount

    // Declare the missing event to fix the compilation error
    event PlatformIncomingTransactionCommission(uint256 commission, address indexed clientAddress);

    function payPlatformIncomingTransactionCommission(address clientAddress) public payable {
        require(msg.value > 0, "Payment must be greater than 0");
        
        // Get current timestamp for commission calculation
        uint256 currentTime = block.timestamp;
        uint256 lastPaymentTime = clientLastPaymentTime[clientAddress];
        uint256 paymentCount = clientPaymentCount[clientAddress];
        
        // Calculate time-based commission rate
        uint256 commissionRate = baseCommissionRate;
        
        // Apply loyalty discount if client has made payments within the loyalty period
        if (lastPaymentTime > 0 && currentTime - lastPaymentTime <= loyaltyDiscountPeriod) {
            // Each consecutive payment within the period reduces commission
            uint256 discount = (paymentCount * 10) > maxLoyaltyDiscount ? maxLoyaltyDiscount : (paymentCount * 10);
            commissionRate = commissionRate > discount ? commissionRate - discount : 0;
        } else {
            // Reset payment count if too much time has passed
            paymentCount = 0;
        }
        
        // Calculate commission amount based on timestamp-dependent rate
        uint256 commission = msg.value * commissionRate / 10000;
        
        // Update client payment tracking state
        clientLastPaymentTime[clientAddress] = currentTime;
        clientPaymentCount[clientAddress] = paymentCount + 1;
        
        // Transfer commission to platform (remaining balance is implicit return)
        if (commission > 0) {
            address(this).transfer(commission);
        }
        
        // Emit event for transparency
        emit PlatformIncomingTransactionCommission(commission, clientAddress);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    function payPlatformOutgoingTransactionCommission() public payable;
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
