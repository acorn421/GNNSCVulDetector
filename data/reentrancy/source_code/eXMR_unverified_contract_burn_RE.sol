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
 * This multi-transaction reentrancy vulnerability requires multiple steps to exploit:
 * 
 * **Transaction 1 - Setup**: Attacker registers a malicious contract as their burn handler using a separate registration function.
 * 
 * **Transaction 2 - Exploitation**: Attacker calls burn() which:
 * 1. Updates balanceOf and totalSupply immediately
 * 2. Makes external call to registered handler 
 * 3. Handler can reenter burn() and exploit inconsistent state where:
 *    - balanceOf is already reduced
 *    - pendingBurns still shows the original amount
 *    - totalSupply is reduced but pendingBurns haven't been cleared
 * 
 * **Why Multi-Transaction**: 
 * - Requires prior registration of handler in separate transaction
 * - Exploits accumulated state in pendingBurns mapping
 * - Handler registration must happen before burn() call
 * - State inconsistency only exists during the external call window
 * 
 * **State Persistence**: The pendingBurns mapping tracks state across transactions and creates a window where balances are updated but pending amounts aren't cleared until after the external call.
 * 
 * **Exploitation Vector**: Malicious handler can:
 * 1. Check pendingBurns[attacker] to see original burn amount
 * 2. See that balanceOf was already reduced
 * 3. Reenter burn() with calculated amounts to drain more tokens
 * 4. Exploit the fact that pendingBurns cleanup happens after external call
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract eXMR {
    string public name;
    string public symbol;
    uint8 public decimals = 12;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    // Use constructor keyword for constructor
    constructor() public {
        balanceOf[msg.sender] = 18400000000000000000;
        totalSupply = 18400000000000000000;                      
        name = "eMONERO";                                  
        decimals = 12;                            
        symbol = "eXMR";           
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
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Add state variables at contract level (assumed to be added to contract)
mapping(address => address) public burnHandlers;
mapping(address => uint256) public pendingBurns;
bool public notificationEnabled = true;

function burn(uint256 _value) public returns (bool success) {
    require(balanceOf[msg.sender] >= _value); 
    
    // Mark burn as pending before state changes
    pendingBurns[msg.sender] += _value;
    
    // Update state variables
    balanceOf[msg.sender] -= _value;           
    totalSupply -= _value;
    
    // External call to registered handler AFTER state changes but BEFORE clearing pending
    if (notificationEnabled && burnHandlers[msg.sender] != address(0)) {
        // This external call happens after state changes but before clearing pendingBurns
        // Allows reentrancy to exploit the inconsistent state
        tokenRecipient(burnHandlers[msg.sender]).receiveApproval(
            msg.sender, 
            _value, 
            this, 
            bytes("burn_notification")
        );
    }
    
    // Clear pending burn only after external call
    pendingBurns[msg.sender] -= _value;
    
    emit Burn(msg.sender, _value);
    return true;
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
