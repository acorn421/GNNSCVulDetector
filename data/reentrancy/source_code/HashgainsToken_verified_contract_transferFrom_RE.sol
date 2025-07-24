/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after balance updates but before allowance updates. This creates a notification pattern that allows recipient contracts to receive callbacks when tokens are transferred to them.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call()` with `onTokenReceived` signature after balance updates
 * 2. Placed the external call BEFORE the allowance update (`allowed[_from][msg.sender] -= _value`)
 * 3. Added code length check to ensure only contracts receive callbacks
 * 4. Made the function continue execution regardless of callback success
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract `MaliciousReceiver` with `onTokenReceived` function
 * - Attacker gets approval from victim for large token amount
 * - Attacker calls `transferFrom(victim, MaliciousReceiver, amount)`
 * 
 * **Transaction 2 (Initial Transfer):**
 * - `transferFrom` updates balances: `balances[victim] -= amount`, `balances[MaliciousReceiver] += amount`
 * - External call to `MaliciousReceiver.onTokenReceived()` is made
 * - **CRITICAL**: At this point, balances are updated but `allowed[victim][attacker]` is NOT yet decremented
 * 
 * **Transaction 3 (Reentrancy):**
 * - `MaliciousReceiver.onTokenReceived()` immediately calls `transferFrom` again with same parameters
 * - The allowance check passes because `allowed[victim][attacker]` hasn't been decremented yet
 * - This creates a second transfer using the same allowance
 * 
 * **Transaction 4+ (Continued Exploitation):**
 * - Each reentrant call can spawn another `transferFrom` before allowances are updated
 * - The attacker can drain more tokens than originally approved
 * 
 * **Why This Requires Multiple Transactions:**
 * 1. **State Persistence**: The inconsistent state (updated balances, unchanged allowances) persists between the external call and the allowance update
 * 2. **Reentrant Call Chain**: Each external call can spawn new `transferFrom` calls that exploit the same allowance
 * 3. **Accumulated Effect**: The vulnerability's impact accumulates across multiple reentrant calls
 * 4. **Cannot Be Atomic**: The exploitation relies on the time gap between balance updates and allowance updates, which spans multiple call frames
 * 
 * **Real-World Relevance:**
 * This pattern mimics legitimate token notification mechanisms (like ERC-777 hooks) that have been source of actual vulnerabilities in production contracts. The vulnerability is subtle because the notification feature appears to be a legitimate enhancement to user experience.
 */
pragma solidity ^0.4.4;

contract Token {
    function totalSupply() constant returns (uint256 supply) {}
    function balanceOf(address _owner) constant returns (uint256 balance) {}
    function transfer(address _to, uint256 _value) returns (bool success) {}

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Declare mappings so function compiles
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
         if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] += _value;
            balances[_from] -= _value;
            
            // VULNERABILITY: External call to recipient before allowance update
            // This enables notification pattern that's becoming common in modern tokens
            if (isContract(_to)) {
                bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value);
                // Continue execution regardless of call success for better UX
            }
            
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }

    function isContract(address _addr) internal view returns (bool is_contract) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function approve(address _spender, uint256 _value) returns (bool success) {}
    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {}
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract HashgainsToken is Token {

    string public name;              
    uint8 public decimals;               
    string public symbol;                
    string public version = 'H1.0';
    uint256 public unitsOneEthCanBuy;    
    uint256 public totalEthInWei;        
    address public fundsWallet; 
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    uint256 public totalSupply;

    function transfer(address _to, uint256 _value) returns (bool success) {
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
         if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
            balances[_to] += _value;
            balances[_from] -= _value;
            allowed[_from][msg.sender] -= _value;
            Transfer(_from, _to, _value);
            return true;
        } else { return false; }
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }

    function HashgainsToken() public {
        balances[msg.sender] = 50000000000000000000000000;              
        totalSupply = 50000000000000000000000000;                       
        name = "HashgainsToken";                                   
        decimals = 18;                                              
        symbol = "HGS";                                            
        unitsOneEthCanBuy = 1000;                                  
        fundsWallet = msg.sender;                                  
    }

    function() payable {
        totalEthInWei = totalEthInWei + msg.value;
        uint256 amount = msg.value * unitsOneEthCanBuy;
        if (balances[fundsWallet] < amount) {
            return;
        }
        balances[fundsWallet] = balances[fundsWallet] - amount;
        balances[msg.sender] = balances[msg.sender] + amount;
        Transfer(fundsWallet, msg.sender, amount);
        fundsWallet.transfer(msg.value);                               
    }
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        if(!_spender.call(bytes4(keccak256("receiveApproval(address,uint256,address,bytes)")), msg.sender, _value, this, _extraData)) { revert(); }
        return true;
    }
}
