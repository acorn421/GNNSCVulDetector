/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call before state updates. The vulnerability allows a malicious contract to re-enter transferOwnership and manipulate the ownership transfer process across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to the new owner contract using `tOwner.call(data)` before updating the `newOwner` state variable
 * 2. The external call notifies the new owner about the ownership transfer using `onOwnershipTransfer(address)` callback
 * 3. Added a code length check to only call contracts (not EOAs) to make the vulnerability more realistic
 * 4. The external call occurs BEFORE the state update (`newOwner = tOwner`), creating the reentrancy window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transferOwnership(maliciousContract)` where `maliciousContract` is controlled by the attacker
 * 2. **During Transaction 1**: The external call to `maliciousContract.onOwnershipTransfer()` executes
 * 3. **Reentrancy**: The malicious contract re-enters `transferOwnership()` with a different address before `newOwner` is set
 * 4. **State Manipulation**: Multiple ownership transfers can be initiated, creating inconsistent state
 * 5. **Transaction 2**: Attacker calls `acceptOwnership()` from the most favorable ownership transfer
 * 6. **Exploitation**: The attacker can choose which ownership transfer to accept, potentially bypassing security checks or creating unexpected behavior
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the initial `transferOwnership()` call to set up the reentrancy conditions
 * - The malicious contract needs to re-enter during the callback to manipulate state
 * - The final `acceptOwnership()` call in a subsequent transaction completes the exploit
 * - State changes from the reentrancy persist between transactions, allowing the attacker to strategically choose which ownership transfer to accept
 * - The vulnerability cannot be exploited in a single atomic transaction because it requires the interaction between the callback and the state persistence across the two-phase ownership transfer process
 * 
 * This creates a realistic, stateful vulnerability where the attacker must carefully orchestrate multiple transactions to exploit the reentrancy condition and manipulate the ownership transfer mechanism.
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
    constructor() public {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the new owner about the ownership transfer
        uint32 size;
        assembly {
            size := extcodesize(tOwner)
        }
        if (size > 0) { // replaces .callcode.length in 0.4.16
            bytes memory data = abi.encodeWithSignature("onOwnershipTransfer(address)", owner);
            tOwner.call(data);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        newOwner = tOwner;
    }
    function acceptOwnership() public {
        require(msg.sender==newOwner && newOwner != 0x0);
        owner = newOwner;
        newOwner = 0x0;
        emit OwnerUpdate(owner, newOwner);
    }

    function freezeAccount(address target, bool freeze) onlyOwner public {
        frozens[target] = freeze;
        emit FrozenFunds(target, freeze);
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
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
}
