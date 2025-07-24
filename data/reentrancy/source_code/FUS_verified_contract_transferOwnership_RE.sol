/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 1. Added `pendingOwner` state variable to track ownership transfer state
 * 2. Added `ownershipTransferInProgress` boolean flag for transfer status
 * 3. Introduced external call `newOwner.call()` before state finalization
 * 4. Added `finalizeOwnershipTransfer()` function for completing transfers
 * 5. Created a two-phase ownership transfer process with persistent state
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 - Initiate Transfer:**
 * - Current owner calls `transferOwnership(attackerContract)`
 * - `pendingOwner` is set to attacker's address
 * - `ownershipTransferInProgress` becomes true
 * - External call to `attackerContract.onOwnershipTransferred()` occurs
 * - During this call, attacker can re-enter OTHER contract functions while ownership is in transition
 * - If external call fails, ownership remains pending (vulnerable state persists)
 * 
 * **Transaction 2+ - Exploit Transition State:**
 * - Attacker exploits the intermediate state where:
 *   - `owner` is still the old owner
 *   - `pendingOwner` is the attacker
 *   - `ownershipTransferInProgress` is true
 * - Attacker can call `finalizeOwnershipTransfer()` to complete the transfer
 * - During the transition window, other functions may have inconsistent access control
 * 
 * **Why Multi-Transaction Nature is Critical:**
 * 1. **State Persistence**: The vulnerable state (`ownershipTransferInProgress=true`) persists between transactions
 * 2. **Accumulated Effect**: Each transaction builds upon the previous state changes
 * 3. **Time Window**: Creates an exploitable window that spans multiple blocks/transactions
 * 4. **Stateful Exploitation**: Requires the attacker to first establish the vulnerable state, then exploit it
 * 
 * **Exploitation Sequence:**
 * 1. **Setup Transaction**: Attacker deploys malicious contract with `onOwnershipTransferred()` function
 * 2. **Trigger Transaction**: Legitimate owner calls `transferOwnership(attackerContract)`
 * 3. **Reentrancy Transaction**: During external call, attacker re-enters and manipulates contract state
 * 4. **Finalization Transaction**: Attacker calls `finalizeOwnershipTransfer()` to complete ownership hijack
 * 
 * **Real-World Vulnerability Pattern:**
 * This mimics actual patterns seen in governance contracts and multi-signature wallets where ownership transfers involve notifications and two-phase processes, creating stateful reentrancy opportunities.
 */
pragma solidity ^0.4.18;

contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
address public pendingOwner;
    bool public ownershipTransferInProgress;

    function transferOwnership(address newOwner) onlyOwner public {
        if (newOwner != address(0)) {
            pendingOwner = newOwner;
            ownershipTransferInProgress = true;
            
            // Notify the new owner before finalizing - VULNERABLE to reentrancy
            bool success = newOwner.call(abi.encodeWithSignature("onOwnershipTransferred(address)", owner));
            
            if (success) {
                owner = newOwner;
                ownershipTransferInProgress = false;
                pendingOwner = address(0);
            } else {
                // If notification fails, ownership transfer is pending
                // This creates a stateful vulnerability window
            }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    function finalizeOwnershipTransfer() public {
        require(ownershipTransferInProgress, "No ownership transfer in progress");
        require(msg.sender == pendingOwner, "Only pending owner can finalize");
        
        owner = pendingOwner;
        ownershipTransferInProgress = false;
        pendingOwner = address(0);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}


contract FUS is owned {
    string public name = 'FusChain';
    string public symbol = 'FUS';
    uint8 public decimals = 18;
    // 10000w  100000000 * 1000000000000000000
    uint public totalSupply = 100000000000000000000000000;

    mapping (address => uint) public balanceOf;
    mapping (address => mapping (address => uint)) public allowance;

    event Transfer(address indexed from, address indexed to, uint value);

    function FUS() public {
        balanceOf[msg.sender] = totalSupply;
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);  
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function () payable public {
        uint etherAmount = msg.value;
        owner.transfer(etherAmount);
    }
}