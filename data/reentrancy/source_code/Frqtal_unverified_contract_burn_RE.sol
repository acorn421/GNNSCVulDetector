/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism to external "burn handler" contracts. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup)**: An attacker first registers a malicious burn handler contract using a setBurnHandler() function (which would need to be added to the contract). This establishes persistent state by storing the handler address in the burnHandlers mapping.
 * 
 * **Transaction 2 (Exploit)**: When the attacker calls burn(), the function performs state updates (reducing balance and totalSupply) but then makes an external call to the registered handler. The malicious handler can then re-enter the burn function or other contract functions while the original burn call is still executing.
 * 
 * **Multi-Transaction Nature**: The vulnerability is stateful because:
 * 1. The burn handler must be registered in a prior transaction and persists in contract storage
 * 2. The external call only occurs if a handler was previously registered
 * 3. The attacker can accumulate state changes across multiple burn operations
 * 4. The handler can manipulate the contract state between the balance reduction and function completion
 * 
 * **Key Vulnerability Points**:
 * - External call after state changes (violates checks-effects-interactions)
 * - Persistent state dependency (burnHandlers mapping)
 * - Callback mechanism allows state manipulation during execution
 * - Multiple transaction sequence required for exploitation
 * 
 * This creates a realistic vulnerability pattern where legitimate burn notification functionality becomes an attack vector through improper state management and external call ordering.
 */
pragma solidity ^0.4.16;
  

contract owned {
    address public owner;

    constructor() public {
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

// Declare the IBurnHandler interface
interface IBurnHandler {
    function onBurn(address from, uint256 value) external;
}

contract Frqtal is owned {
    
    string public name;
    string public symbol;
    uint8 public decimals = 18;    
    uint256 public totalSupply;

    
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    // Declare the burnHandlers mapping
    mapping(address => address) public burnHandlers;

    
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    
    event Burn(address indexed from, uint256 value);

    
    constructor(
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

        emit Transfer(_from, _to, _value);
        
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
        emit Approval(msg.sender, _spender, _value);
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
        emit Burn(msg.sender, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify burn handler contract if registered
        if (burnHandlers[msg.sender] != address(0)) {
            IBurnHandler(burnHandlers[msg.sender]).onBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }
}
