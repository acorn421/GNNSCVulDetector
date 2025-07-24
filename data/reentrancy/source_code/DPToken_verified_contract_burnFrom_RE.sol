/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding a pending burn tracking mechanism and an external call notification system. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added `pendingBurns` mapping to track accounts with pending burn operations
 * 2. Added `pendingBurnAmounts` mapping to store the amount being burned
 * 3. Introduced an external call to `_from` address via `onTokenBurn()` callback before state updates
 * 4. Added pending burn state management that creates exploitation windows
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `burnFrom()` targeting a contract they control
 * 2. **During Transaction 1**: The external call triggers the attacker's `onTokenBurn()` callback
 * 3. **Within Callback**: Attacker calls `burnFrom()` again (blocked by `pendingBurns` check)
 * 4. **Transaction 2**: After Transaction 1 completes, attacker calls `burnFrom()` again
 * 5. **Exploitation**: Due to state inconsistencies from the first call, the second call operates on outdated allowance/balance values
 * 
 * **Why Multi-Transaction Required:**
 * - The `pendingBurns` check prevents immediate reentrancy within the same transaction
 * - The vulnerability manifests when the pending state is cleared but external contracts have been notified
 * - Attackers must wait for the first transaction to complete before exploiting the state inconsistency
 * - The notification mechanism creates a window where external contracts can prepare for the second exploitative call
 * 
 * **Realistic Attack Vector:**
 * An attacker deploys a contract that implements `onTokenBurn()` to monitor burn notifications. Between the notification and state clearing, the attacker can exploit timing dependencies or use the notification to front-run other operations, effectively burning tokens multiple times or manipulating allowances across separate transactions.
 */
pragma solidity ^0.4.19;

interface tokenRecipients3dp { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract DPToken {
  string public name = "3DP-Token";
  string public symbol = "3DP";
  uint8 public  decimals = 2;
  uint256 public totalSupply=30000000000;
  
  mapping (address => uint256) public balanceOf;
  mapping (address => mapping (address => uint256)) public allowance;
  event Transfer(address indexed from, address indexed to, uint256 value);
  event Burn(address indexed from, uint256 value);

    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = 30000000000;  
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;                   
        symbol = tokenSymbol;               
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipients3dp spender = tokenRecipients3dp(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                      
        emit Burn(msg.sender, _value);
        return true;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping (address => bool) public pendingBurns;
    mapping (address => uint256) public pendingBurnAmounts;
    
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        require(balanceOf[_from] >= _value);              
        require(_value <= allowance[_from][msg.sender]);  
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Mark burn as pending to prevent double execution
        require(!pendingBurns[_from], "Burn already pending");
        pendingBurns[_from] = true;
        pendingBurnAmounts[_from] = _value;
        
        // Notify the account being burned from - VULNERABLE: External call before state update
        if (isContract(_from)) {
            // Must use different variable name for return value to avoid shadowing
            _from.call(abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value));
            // Continue execution regardless of call success
        }
        
        // State updates after external call - VULNERABLE TO REENTRANCY
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                       
        allowance[_from][msg.sender] -= _value;           
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        totalSupply -= _value;
        
        // Clear pending burn state
        pendingBurns[_from] = false;
        pendingBurnAmounts[_from] = 0;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Burn(_from, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
