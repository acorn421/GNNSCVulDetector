/*
 * ===== SmartInject Injection Details =====
 * Function      : payPlatformOutgoingTransactionCommission
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 5 findings
 * Total Found   : 10 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 * ... and 2 more
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability that requires multiple function calls to exploit. The vulnerability introduces:
 * 
 * 1. **State Persistence**: Added `pendingCommissions` mapping to track accumulated commission payments across transactions and `commissionProcessing` mapping to track processing state.
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls `payPlatformOutgoingTransactionCommission()` with ETH, triggering the `onCommissionReceived` callback before state is fully updated
 *    - **Transaction 2**: Attacker calls `processAccumulatedCommissions()` which triggers another callback before clearing the pending commission state
 *    - **Transaction 3+**: Attacker can repeat the process or manipulate state during callbacks
 * 
 * 3. **Reentrancy Vulnerability Points**:
 *    - External call to `msg.sender.call()` with `onCommissionReceived` callback before `commissionProcessing` state is set
 *    - External call to `msg.sender.call()` with `onCommissionProcessed` callback before state cleanup
 *    - State updates happen after external calls, creating reentrancy windows
 * 
 * 4. **Stateful Nature**: The vulnerability depends on accumulated state from previous transactions stored in `pendingCommissions` mapping, making it impossible to exploit in a single transaction.
 * 
 * 5. **Realistic Implementation**: The callbacks appear as legitimate notification mechanisms that could realistically exist in production code for commission processing systems.
 * 
 * The attacker can exploit this by:
 * - Implementing malicious callback functions that re-enter the contract
 * - Manipulating the commission accounting across multiple transactions
 * - Exploiting the time window between external calls and state updates
 * - Accumulating pending commissions and then manipulating their processing
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// State variable to track pending commission payments
mapping(address => uint256) public pendingCommissions;
mapping(address => bool) public commissionProcessing;

// Declare event to match the emit usage in payPlatformOutgoingTransactionCommission
    event PlatformOutgoingTransactionCommission(uint256 amount);

function payPlatformOutgoingTransactionCommission() public payable {
    // Allow external contracts to register commission callbacks
    if (msg.value > 0) {
        pendingCommissions[msg.sender] += msg.value;
        
        // External call to sender before state cleanup - vulnerable to reentrancy
        if (msg.sender != address(this)) {
            // Call back to sender contract to notify of commission received
            bool success = msg.sender.call(abi.encodeWithSignature("onCommissionReceived(uint256)", msg.value));
            require(success, "Callback failed");
        }
        
        // State update happens after external call - creates reentrancy window
        commissionProcessing[msg.sender] = true;
        
        emit PlatformOutgoingTransactionCommission(msg.value);
    }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}

// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Function to process accumulated commissions (vulnerable to manipulation)
function processAccumulatedCommissions() public {
    require(pendingCommissions[msg.sender] > 0, "No pending commissions");
    require(!commissionProcessing[msg.sender], "Already processing");
    
    uint256 amount = pendingCommissions[msg.sender];
    
    // External call before state cleanup - second vulnerability point
    bool success = msg.sender.call(abi.encodeWithSignature("onCommissionProcessed(uint256)", amount));
    require(success, "Processing callback failed");
    
    // State cleanup happens after external call
    pendingCommissions[msg.sender] = 0;
    commissionProcessing[msg.sender] = false;
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
