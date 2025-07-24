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
 * **Vulnerability Injection Details:**
 * 
 * **1. Changes Made:**
 * - Added `pendingBurns` mapping to track burn operations in progress
 * - Introduced external call to `_from` address via low-level `call()` to notify about burns
 * - Moved critical state updates (balance, allowance, totalSupply) to occur AFTER the external call
 * - Added pending burn status tracking that gets cleared after state updates
 * 
 * **2. Multi-Transaction Exploitation Mechanism:**
 * The vulnerability requires a sophisticated multi-transaction attack:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract with `onTokenBurn` function
 * - Attacker obtains allowance to burn tokens from the malicious contract address
 * 
 * **Transaction 2 (Initial Exploitation):**
 * - Attacker calls `burnFrom(maliciousContract, amount)`
 * - Function passes initial checks (balance >= amount, allowance >= amount)
 * - `pendingBurns[maliciousContract]` set to true
 * - External call triggers `maliciousContract.onTokenBurn()`
 * - **Reentrancy occurs**: Malicious contract calls `burnFrom` again
 * - During reentrancy, state hasn't been updated yet, so checks still pass
 * - Multiple burns can be triggered before any state updates occur
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - Attacker can continue exploiting across multiple transactions
 * - Each transaction can trigger multiple reentrant calls
 * - State inconsistencies accumulate across transactions
 * - Total burned amount exceeds allowance and available balance
 * 
 * **3. Why Multi-Transaction Dependency:**
 * - **State Accumulation**: The vulnerability relies on accumulated state changes across multiple transactions
 * - **Allowance Exploitation**: Attacker needs multiple transactions to fully exploit allowance beyond intended limits
 * - **Balance Manipulation**: Multiple transactions allow draining more tokens than should be possible
 * - **Persistent State Inconsistency**: The `pendingBurns` mapping creates persistent state that can be exploited across transaction boundaries
 * 
 * **4. Realistic Attack Scenario:**
 * - Attacker could be a supposedly trusted DeFi protocol with burn privileges
 * - The external call appears legitimate (notifying token holder about burns)
 * - The vulnerability allows the attacker to burn more tokens than their allowance permits
 * - Multiple transactions make the attack less detectable and more damaging
 * 
 * This creates a stateful, multi-transaction reentrancy vulnerability that requires sequences of calls to fully exploit and causes persistent state corruption across multiple transactions.
 */
pragma solidity ^0.4.16;
  

contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract Frqtal is owned {
    
    string public name;
    string public symbol;
    uint8 public decimals = 18;    
    uint256 public totalSupply;

    
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    
    event Burn(address indexed from, uint256 value);

    
    function Frqtal(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  
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

        Transfer(_from, _to, _value);
        
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    
    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

   
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                      
        Burn(msg.sender, _value);
        return true;
    }

    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping (address => bool) public pendingBurns;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Mark burn as pending to prevent double-spending
        pendingBurns[_from] = true;
        
        // Notify the token holder about the burn through external call
        if (isContract(_from)) {
            _from.call(
                bytes4(keccak256("onTokenBurn(address,uint256)")), msg.sender, _value
            );
            // Continue regardless of call success for backward compatibility
        }
        
        // State updates happen after external call - vulnerability window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        totalSupply -= _value;
        
        // Clear pending status
        pendingBurns[_from] = false;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }

    // Helper function for contract code size (since .code is not available in 0.4.x)
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
