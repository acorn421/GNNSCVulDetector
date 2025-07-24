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
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a sophisticated timestamp dependence vulnerability that requires multiple transactions to exploit. The vulnerability creates a flawed "rapid transaction discount" system that:
 * 
 * 1. **State Persistence**: Uses persistent mappings (lastCommissionTimestamp, commissionMultiplier) to track timing patterns across transactions
 * 2. **Multi-Transaction Exploitation**: Requires at least 2 transactions to build up exploitable state - first transaction establishes baseline, subsequent transactions can manipulate timing
 * 3. **Timestamp Manipulation**: Uses block.timestamp for critical commission calculations, allowing miners to manipulate transaction timing
 * 4. **Compound Vulnerability**: The multiplier accumulates over rapid transactions, creating larger payouts over time rather than discounts
 * 
 * **Multi-Transaction Exploitation Path:**
 * - **Transaction 1**: Establishes initial timestamp and 100% multiplier
 * - **Transaction 2+**: Attacker/miner manipulates block.timestamp to create artificially small timeDiff values, causing commissionMultiplier to increase rather than decrease
 * - **Result**: Multiple rapid transactions with manipulated timestamps result in inflated commission payments
 * 
 * **Why Multi-Transaction Required:**
 * - Single transaction cannot exploit because lastCommissionTimestamp starts at 0
 * - Vulnerability requires accumulated state from previous transactions
 * - Timing manipulation becomes effective only after establishing baseline timing patterns
 * - The multiplier builds up over sequential transactions, not within a single call
 * 
 * The vulnerability is realistic because it mimics real-world attempts to implement time-based incentives but fails to properly validate timestamp inputs and has inverted logic in the discount calculation.
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

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
}

/* Required code start */
contract MarketplaceProxy {
    // State variables required by injected vulnerability
    mapping(address => uint256) public lastCommissionTimestamp;
    mapping(address => uint256) public commissionMultiplier;
    uint256 public timeBasedDiscountWindow = 300; // 5 minutes in seconds
    uint256 public maxMultiplier = 150; // 150% max multiplier
    uint256 public contract_balance; // Used for tracking adjusted commissions

    function calculatePlatformCommission(uint256 weiAmount) public view returns (uint256);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    function payPlatformIncomingTransactionCommission(address clientAddress) public payable {
        // Update commission multiplier based on timestamp patterns
        uint256 currentTime = block.timestamp;
        uint256 lastTime = lastCommissionTimestamp[clientAddress];
        
        // If first transaction or after discount window, reset multiplier
        if (lastTime == 0 || currentTime >= lastTime + timeBasedDiscountWindow) {
            commissionMultiplier[clientAddress] = 100; // Start at 100% (no discount)
        } else {
            // Rapid transactions get "discounts" that compound over time
            // This creates timing manipulation vulnerability
            uint256 timeDiff = currentTime - lastTime;
            uint256 discountFactor = (timeBasedDiscountWindow - timeDiff) * 10 / timeBasedDiscountWindow;
            
            // Increase multiplier for rapid transactions (opposite of intended logic)
            commissionMultiplier[clientAddress] = commissionMultiplier[clientAddress] + discountFactor;
            
            // Cap the multiplier to prevent obvious overflow
            if (commissionMultiplier[clientAddress] > maxMultiplier) {
                commissionMultiplier[clientAddress] = maxMultiplier;
            }
        }
        
        // Calculate commission based on accumulated multiplier
        uint256 adjustedAmount = msg.value * commissionMultiplier[clientAddress] / 100;
        
        // Store timestamp for next calculation
        lastCommissionTimestamp[clientAddress] = currentTime;
        
        // Update contract balance with adjusted amount
        contract_balance += adjustedAmount;
        
        // Forward to actual marketplace with adjusted amount
        // (Original proxy functionality preserved)
        if (adjustedAmount > 0) {
            // Forward the commission payment
            address(this).call.value(adjustedAmount)(
                abi.encodeWithSignature("payPlatformIncomingTransactionCommission(address)", clientAddress)
            );
        }
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
