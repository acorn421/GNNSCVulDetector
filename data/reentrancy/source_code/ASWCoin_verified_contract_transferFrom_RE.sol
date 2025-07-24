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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address for transfer notification. The call occurs after balance updates but before allowance reduction, creating a window where state is inconsistent across transactions. This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)` after balance updates
 * 2. Placed the call strategically between balance modifications and allowance reduction
 * 3. The call notifies the recipient about the transfer, which is a realistic feature in token contracts
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls transferFrom, triggering the callback to their malicious contract
 * 2. **During Callback**: Malicious contract can observe that balances have been updated but allowances haven't been reduced yet
 * 3. **Transaction 2**: From within the callback, the malicious contract can call transferFrom again with the same allowance
 * 4. **State Accumulation**: Each reentrancy call builds up inconsistent state - balances get updated multiple times while allowances are only reduced once per call completion
 * 5. **Result**: Attacker can transfer more tokens than their allowance permits by exploiting the state inconsistency window
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability cannot be exploited in a single atomic transaction because the external call creates a dependency on external contract behavior
 * - The malicious contract must execute callback logic in a separate execution context
 * - State inconsistency accumulates across multiple nested calls, requiring the transaction sequence to build up the exploitable condition
 * - The allowance reduction happens at the end of each call, so multiple calls are needed to exploit the timing window before this reduction occurs
 * 
 * **Realistic Nature:**
 * - Token transfer notifications are common in modern ERC20 implementations
 * - The callback pattern is used in many DeFi protocols for hooks and notifications
 * - The vulnerability follows real-world patterns seen in production contracts where external calls are placed at vulnerable points in the state transition sequence
 */
pragma solidity ^0.4.6;

contract ASWCoin {
    
    // totalSupply = maximum 210000 with 18 decimals;   
    uint256 public supply = 210000000000000000000000;  
    uint8   public decimals = 18;    
    string  public standard = 'ERC20 Token';
    string  public name = "ASWCoin";
    string  public symbol = "ASW";
    uint256 public circulatingSupply = 0;   
    uint256 availableSupply;              
    uint256 price= 1;                          	
    uint256 crowdsaleClosed = 0;                 
    address multisig = msg.sender;
    address owner = msg.sender;  

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;	
	
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);    

    function totalSupply() constant returns (uint256 supply) {
        supply = supply;
    }
    
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
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient about the transfer - introduces reentrancy vulnerability
            if (_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
                // Callback executed successfully
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
	
    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }
	
    function transferOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    }	
	
    function () payable {
        if (crowdsaleClosed > 0) throw;		
        if (msg.value == 0) {
          throw;
        }		
        if (!multisig.send(msg.value)) {
          throw;
        }		
        uint token = msg.value * price;		
		availableSupply = supply - circulatingSupply;
        if (token > availableSupply) {
          throw;
        }		
        circulatingSupply += token;
        balances[msg.sender] += token;
    }
	
    function setPrice(uint256 newSellPrice) onlyOwner {
        price = newSellPrice;
    }
	
    function stoppCrowdsale(uint256 newStoppSign) onlyOwner {
        crowdsaleClosed = newStoppSign;
    }		

    function setMultisigAddress(address newMultisig) onlyOwner {
        multisig = newMultisig;
    }	
	
}