/*
 * ===== SmartInject Injection Details =====
 * Function      : payPlatformIncomingTransactionCommission
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 6 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 * ... and 3 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Added `pendingCommissions` mapping to track commission amounts and `commissionProcessing` flag to track processing state
 * 2. **Vulnerable External Call**: Added an external call to the client address with `onCommissionReceived` callback before finalizing state updates
 * 3. **State Update After External Call**: Moved the critical `contract_balance` update to occur AFTER the external call, violating the Checks-Effects-Interactions pattern
 * 4. **Multi-Transaction Exploitation Path**: The vulnerability requires multiple transactions to exploit effectively:
 *    - **Transaction 1**: Attacker calls function, pendingCommissions is updated, external call is made
 *    - **Transaction 2**: During the external call, malicious contract reenters the function
 *    - **Transaction 3**: The reentrant call sees inconsistent state (pendingCommissions updated but contract_balance not yet updated)
 *    - **Transaction 4**: Attacker can manipulate the accumulated state across multiple calls
 * 
 * **Why Multi-Transaction**: The vulnerability is multi-transaction because:
 * - The `pendingCommissions` state persists between transactions
 * - The attacker needs to set up the initial state in one transaction
 * - The reentrancy exploitation happens in subsequent transactions
 * - The accumulated `pendingCommissions` across multiple calls creates the attack vector
 * - Single transaction exploitation is prevented by the state dependencies
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// State variable to track pending commission payments
using SafeMath for uint256;
mapping(address => uint256) public pendingCommissions;
mapping(address => bool) public commissionProcessing;
uint256 public contract_balance; // <-- Added state variable for contract_balance

// Event declaration required for emit statement
    event PlatformIncomingTransactionCommission(uint256 amount, address indexed clientAddress);

function payPlatformIncomingTransactionCommission(address clientAddress) public payable {
    require(msg.value > 0, "Commission amount must be greater than 0");
    require(clientAddress != address(0), "Invalid client address");
    
    // Record the pending commission (state change before external call)
    pendingCommissions[clientAddress] = pendingCommissions[clientAddress].add(msg.value);
    
    // Mark commission as being processed
    commissionProcessing[clientAddress] = true;
    
    // External call to client contract - VULNERABLE TO REENTRANCY
    // This allows the client to call back into this function before state is finalized
    if (clientAddress.call.value(0)(bytes4(keccak256("onCommissionReceived(uint256)")), msg.value)) {
        // Call succeeded, continue processing
    }
    
    // Update contract balance after external call (VULNERABLE PATTERN)
    // This state update happens after the external call, creating reentrancy window
    contract_balance = contract_balance.add(msg.value);
    
    // Clear processing flag after state update
    commissionProcessing[clientAddress] = false;
    
    emit PlatformIncomingTransactionCommission(msg.value, clientAddress);
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
