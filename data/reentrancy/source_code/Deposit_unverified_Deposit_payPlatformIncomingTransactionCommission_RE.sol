/*
 * ===== SmartInject Injection Details =====
 * Function      : payPlatformIncomingTransactionCommission
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding State Variables**: Three new state variables track transaction processing state across multiple calls:
 *    - `processingTransaction`: Tracks if a transaction is currently being processed for a client
 *    - `pendingCommissions`: Accumulates commission amounts before they're finalized
 *    - `contract_balance`: Main contract balance that gets updated after external calls
 * 
 * 2. **External Call Before State Finalization**: The function makes an external call to the client contract using `clientAddress.call()` to notify about commission receipt. This external call happens BEFORE the final state updates.
 * 
 * 3. **State Updates After External Call**: Critical state changes (updating `contract_balance`, clearing `pendingCommissions`) happen after the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker calls `payPlatformIncomingTransactionCommission` with a malicious contract address
 * - `pendingCommissions[attacker]` is set to `msg.value`
 * - `processingTransaction[attacker]` is set to `true`
 * - External call to attacker's contract triggers the `onCommissionReceived` callback
 * 
 * **Transaction 2 (Reentrancy)**:
 * - During the external call, attacker's contract reenters `payPlatformIncomingTransactionCommission`
 * - Since `processingTransaction[attacker]` is still `true` and `pendingCommissions[attacker]` still contains the previous amount, the attacker can manipulate this state
 * - The attacker can call the function again with additional value, causing `pendingCommissions[attacker]` to accumulate
 * 
 * **Transaction 3+ (Exploitation)**:
 * - Multiple reentrant calls can accumulate large amounts in `pendingCommissions`
 * - When the original call finally completes, `contract_balance` is updated with the accumulated (inflated) amount
 * - The attacker has effectively multiplied their commission credits
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: The vulnerability relies on accumulating state in `pendingCommissions` across multiple reentrant calls
 * 2. **Processing Flag**: The `processingTransaction` flag creates a window where multiple calls can interfere with each other
 * 3. **Delayed State Finalization**: The final state update happens after all external calls complete, allowing multiple transactions to manipulate the intermediate state
 * 4. **Cross-Transaction Dependencies**: Each reentrant call depends on the state set by previous calls in the sequence
 * 
 * This creates a realistic vulnerability where the attacker needs to orchestrate multiple function calls to exploit the inconsistent state management between external calls and state updates.
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
        require(b > 0); 
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
    function calculatePlatformCommission(uint256 weiAmount) public view returns (uint256);
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// State variables to track transaction processing
mapping(address => bool) public processingTransaction;
mapping(address => uint256) public pendingCommissions;
uint256 public contract_balance;

function payPlatformIncomingTransactionCommission(address clientAddress) public payable {
    // Track pending commission for this client
    pendingCommissions[clientAddress] += msg.value;
    
    // Mark transaction as being processed
    processingTransaction[clientAddress] = true;
    
    // External call to client contract for commission validation/notification
    // This creates the reentrancy opportunity
    // Workaround for Solidity <0.5.0 as address.code is not available - check for contract using extcodesize
    uint256 size;
    assembly { size := extcodesize(clientAddress) }
    if (size > 0) {
        (bool success, ) = clientAddress.call(abi.encodeWithSignature("onCommissionReceived(uint256)", msg.value));
    }
    
    // Update contract balance (this happens after external call)
    contract_balance += pendingCommissions[clientAddress];
    
    // Clear pending commission and processing flag
    pendingCommissions[clientAddress] = 0;
    processingTransaction[clientAddress] = false;
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
        uint256 nextPaymentTotalAmount;
        uint256 nextPaymentDepositCommission;   
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

    function () public payable {
        handleIncomingPayment(msg.sender, msg.value);
    }

    function fromPaymentGateway(address clientAddress) public payable {
        handleIncomingPayment(clientAddress, msg.value);
    }

    function handleIncomingPayment(address clientAddress, uint256 amount) private {
        ClientDeposit storage clientDeposit = depositsMap[clientAddress];

        require(clientDeposit.exists);
        require(clientDeposit.nextPaymentTotalAmount == amount);

        /* Required code start */
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

        clientDeposit.balance += amount.sub(clientDeposit.nextPaymentPlatformCommission).sub(clientDeposit.nextPaymentDepositCommission);
        emit DepositCommission(clientDeposit.nextPaymentDepositCommission, clientAddress);
    }

    function addEth() public payable onlyOwner {

    }

    function claim(address from, address to, uint256 amount) public onlyOwner{
        require(depositsMap[from].exists);

        /* Required code start */
        uint256 commission = mp.calculatePlatformCommission(amount);

        require(address(this).balance > amount.add(commission));
        require(depositsMap[from].balance >= amount);

        mp.payPlatformOutgoingTransactionCommission.value(commission)();
        emit PlatformOutgoingTransactionCommission(commission);
        /* Required code end */

        depositsMap[from].balance -= amount;

        to.transfer(amount);
    }

    function isClient(address clientAddress) public view onlyOwner returns(bool) {
        return depositsMap[clientAddress].exists;
    }

    function addClient(address clientAddress, uint256 _nextPaymentTotalAmount, uint256 _nextPaymentDepositCommission, uint256 _nextPaymentPlatformCommission) public onlyOwner {
        require( (clientAddress != address(0)));

        require(!depositsMap[clientAddress].exists);

        depositsMap[clientAddress] = ClientDeposit(
            0,                                  // balance
            _nextPaymentTotalAmount,            // nextPaymentTotalAmount
            _nextPaymentDepositCommission,      // nextPaymentDepositCommission
            _nextPaymentPlatformCommission,     // nextPaymentPlatformCommission
            true,                               // exists
            false                               // isBlocked
        );
    }

    function getClientBalance(address clientAddress) public view returns(uint256) {
        return depositsMap[clientAddress].balance;
    }

    function repeatedPayment(address clientAddress, uint256 _nextPaymentTotalAmount, uint256 _nextPaymentDepositCommission, uint256 _nextPaymentPlatformCommission) public onlyOwner {
        ClientDeposit storage clientDeposit = depositsMap[clientAddress];

        require(clientAddress != address(0));
        require(clientDeposit.exists);

        clientDeposit.nextPaymentTotalAmount = _nextPaymentTotalAmount;
        clientDeposit.nextPaymentDepositCommission = _nextPaymentDepositCommission;
        clientDeposit.nextPaymentPlatformCommission = _nextPaymentPlatformCommission;
    }
}
