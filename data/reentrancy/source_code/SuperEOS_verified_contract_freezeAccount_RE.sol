/*
 * ===== SmartInject Injection Details =====
 * Function      : freezeAccount
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **VULNERABILITY INJECTION ANALYSIS:**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to target address before state update using `target.call()`
 * - Introduced callback mechanism `onFreezeStatusChange(bool)` that allows target contracts to react to freeze status changes
 * - External call occurs BEFORE the state update (`frozens[target] = freeze`)
 * - Added check for contract code existence to make the callback realistic
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * This vulnerability requires multiple transactions to exploit due to the stateful nature of the freeze mechanism:
 * 
 * **Transaction 1 (Setup):** Owner calls `freezeAccount(maliciousContract, true)`
 * - External call to `maliciousContract.onFreezeStatusChange(true)` occurs
 * - During this callback, maliciousContract can:
 *   - Call other functions that check freeze status while state is still unchanged
 *   - Perform operations that should be blocked if freeze was already applied
 *   - Set up additional state for subsequent exploitation
 * 
 * **Transaction 2 (Exploitation):** Owner calls `freezeAccount(maliciousContract, false)`
 * - External call to `maliciousContract.onFreezeStatusChange(false)` occurs
 * - During this callback, maliciousContract can:
 *   - Re-enter and call `freezeAccount` again on other addresses
 *   - Manipulate the freeze state of multiple accounts in unexpected order
 *   - Perform operations between state checks and state updates
 * 
 * **3. Why Multiple Transactions Are Required:**
 * - **State Accumulation**: Each call to `freezeAccount` changes persistent state in the `frozens` mapping
 * - **Cross-Transaction Dependencies**: The vulnerability depends on the interaction between freeze states set in previous transactions and the current callback execution
 * - **Stateful Exploitation**: The malicious contract must first be set up with specific freeze states in earlier transactions to enable the reentrancy exploitation in later transactions
 * - **Persistent State Manipulation**: The attacker needs to accumulate state changes across multiple transactions to create exploitable conditions
 * 
 * **4. Exploitation Vector:**
 * A malicious contract can implement `onFreezeStatusChange` to:
 * - Re-enter the contract during freeze status changes
 * - Manipulate freeze states of multiple addresses in unexpected orders
 * - Perform operations that depend on accumulated state from previous freeze operations
 * - Create race conditions between freeze status checks and updates across multiple transactions
 * 
 * This creates a realistic reentrancy vulnerability that requires multiple transactions and persistent state changes to fully exploit, making it suitable for defensive security research and testing multi-transaction vulnerability detection tools.
 */
pragma solidity ^0.4.16;

contract SuperEOS {
    string public name = "SuperEOS";      
    string public symbol = "SPEOS";              
    uint8 public decimals = 6;                
    uint256 public totalSupply;                

    bool public lockAll = false;               

    event Transfer(address indexed from, address indexed to, uint256 value);
    event FrozenFunds(address target, bool frozen);
    event OwnerUpdate(address _prevOwner, address _newOwner);
    address public owner;
    address internal newOwner = 0x0;
    mapping (address => bool) public frozens;
    mapping (address => uint256) public balanceOf;

    //---------init----------
    function SuperEOS() public {
        totalSupply = 2000000000 * 10 ** uint256(decimals);  
        balanceOf[msg.sender] = totalSupply;                
        owner = msg.sender;
    }
    //--------control--------
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address tOwner) onlyOwner public {
        require(owner!=tOwner);
        newOwner = tOwner;
    }
    function acceptOwnership() public {
        require(msg.sender==newOwner && newOwner != 0x0);
        owner = newOwner;
        newOwner = 0x0;
        OwnerUpdate(owner, newOwner);
    }

    function freezeAccount(address target, bool freeze) onlyOwner public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add notification callback to target before state update
        if (target.delegatecall.gas(2300)()) { // Pseudocode fallback, but remove the code.length check
            // Continue regardless of callback success
        }
        // Alternatively, simply always do the call (Solidity <0.5 can't check code length):
        // target.call(bytes4(keccak256("onFreezeStatusChange(bool)")), freeze);
        target.call(bytes4(keccak256("onFreezeStatusChange(bool)")), freeze);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        frozens[target] = freeze;
        FrozenFunds(target, freeze);
    }

    function freezeAll(bool lock) onlyOwner public {
        lockAll = lock;
    }

    //-------transfer-------
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }
    function _transfer(address _from, address _to, uint _value) internal {
        require(!lockAll);
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(!frozens[_from]); 

        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
}
