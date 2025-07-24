/*
 * ===== SmartInject Injection Details =====
 * Function      : makeTransfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism that allows external contracts to re-enter the makeTransfer function. The vulnerability requires:
 * 
 * 1. **Transaction 1**: Attacker registers a callback using registerCallback() with high gas limit
 * 2. **Transaction 2**: When makeTransfer() is called, the callback is triggered BEFORE transferPointer is updated
 * 3. **Reentrancy**: The callback can call makeTransfer() again, potentially manipulating the transfer queue or causing double-spending
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Phase (Transaction 1)**: Attacker deploys a malicious contract and calls registerCallback(1000000) to register for callbacks with high gas limit
 * 2. **Exploitation Phase (Transaction 2)**: When makeTransfer() is called by legitimate users, the malicious contract receives onTransferPending() callback
 * 3. **Reentrancy Attack**: The callback function can re-enter makeTransfer(), potentially:
 *    - Manipulating the transferPointer before it's updated
 *    - Causing transfers to be processed multiple times
 *    - Interfering with the transfer queue order
 *    - Draining more funds than intended
 * 
 * **Why Multi-Transaction is Required:**
 * - The callback registration must occur in a separate transaction before the vulnerability can be exploited
 * - State persistence (transferCallbacks mapping) enables the attack across transaction boundaries
 * - The vulnerability cannot be exploited without prior state setup through registerCallback()
 * - Multiple calls to makeTransfer() can compound the attack effects
 * 
 * **Vulnerability Mechanics:**
 * - External call happens before transferPointer increment (checks-effects-interactions violation)
 * - Callback system allows controlled reentrancy with configurable gas limits
 * - State variables persist between transactions enabling stateful attacks
 * - Multiple transaction sequences can be used to manipulate transfer ordering and amounts
 */
pragma solidity ^0.4.16;

contract LineOfTransfers {

    address[] public accounts;
    uint[] public values;
    
    uint public transferPointer = 0;

    address public owner;

    event Transfer(address to, uint amount);

    modifier hasBalance(uint index) {
        require(this.balance >= values[index]);
        _;
    }
    
    modifier existingIndex(uint index) {
        assert(index < accounts.length);
        assert(index < values.length);
        _;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function () payable public {}

    function LineOfTransfers() public {
        owner = msg.sender;
    }

    function transferTo(uint index) existingIndex(index) hasBalance(index) internal returns (bool) {
        uint amount = values[index];
        accounts[index].transfer(amount);

        Transfer(accounts[index], amount);
        return true;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => bool) public transferCallbacks;
    mapping(address => uint) public callbackGasLimits;
    
    function makeTransfer(uint times) public {
        while(times > 0) {
            uint currentIndex = transferPointer;
            address recipient = accounts[currentIndex];
            
            // External call before state update - vulnerable to reentrancy
            if (transferCallbacks[recipient]) {
                recipient.call.gas(callbackGasLimits[recipient] == 0 ? 2300 : callbackGasLimits[recipient])(
                    bytes4(keccak256("onTransferPending(uint256,uint256)")), 
                    currentIndex, 
                    values[currentIndex]
                );
            }
            
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            transferTo(transferPointer);
            transferPointer++;
            times--;
        }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function registerCallback(uint gasLimit) external {
        transferCallbacks[msg.sender] = true;
        callbackGasLimits[msg.sender] = gasLimit;
    }
    
    function unregisterCallback() external {
        transferCallbacks[msg.sender] = false;
        callbackGasLimits[msg.sender] = 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    
    function getBalance() constant returns (uint balance) {
        return this.balance;
    }
    
    function addData(address[] _accounts, uint[] _values) onlyOwner {
        require(_accounts.length == _values.length);
        
        for (uint i = 0; i < _accounts.length; i++) {
            accounts.push(_accounts[i]);
            values.push(_values[i]);
        }
    }
    
    
    function terminate() onlyOwner {
        selfdestruct(owner);
    }
}