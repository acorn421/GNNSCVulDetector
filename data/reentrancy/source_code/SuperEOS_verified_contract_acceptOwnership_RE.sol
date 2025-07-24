/*
 * ===== SmartInject Injection Details =====
 * Function      : acceptOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Before State Update**: Added an external call to the previous owner's address using `owner.call(callData)` that attempts to notify them about the ownership transfer. This call happens BEFORE the ownership state is finalized.
 * 
 * 2. **State Inconsistency Window**: During the external call, the contract state is inconsistent:
 *    - `newOwner` is still set to the pending owner
 *    - `owner` is still the old owner
 *    - The ownership transfer hasn't completed yet
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls `acceptOwnership()`, triggering the external call to the old owner
 *    - **During External Call**: The old owner (if it's a malicious contract) can re-enter and call other functions that depend on ownership state
 *    - **Transaction 2+**: The attacker can exploit the intermediate state where ownership validation has passed but transfer isn't complete
 *    - **State Accumulation**: The vulnerability requires multiple calls because the attacker needs to first establish the intermediate state, then exploit it
 * 
 * 4. **Realistic Vulnerability Pattern**: The notification mechanism is a common real-world pattern where contracts notify stakeholders about important state changes, making this injection realistic and subtle.
 * 
 * 5. **Exploitation Scenario**:
 *    - Attacker becomes `newOwner` through legitimate `transferOwnership()` call
 *    - Attacker calls `acceptOwnership()` 
 *    - During the external call to old owner, the old owner (malicious contract) can:
 *      - Call other functions that still see the old owner as valid
 *      - Trigger additional state changes before ownership fully transfers
 *      - Coordinate with other transactions to exploit the inconsistent state
 *    - The vulnerability is only exploitable through this multi-step process involving state persistence across transactions
 * 
 * This creates a genuine multi-transaction reentrancy vulnerability where the exploit requires coordinated transactions and depends on accumulated state changes.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify previous owner before state update
        if (owner != 0x0) {
            // Attempt to call onOwnershipTransfer if it exists
            bytes memory callData = abi.encodeWithSignature("onOwnershipTransfer(address,address)", owner, newOwner);
            owner.call(callData);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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