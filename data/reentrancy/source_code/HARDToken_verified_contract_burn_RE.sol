/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burnRegistry contract after the balance check but before state updates. This creates a classic checks-effects-interactions pattern violation where:
 * 
 * 1. **State Persistence**: The vulnerability exploits persistent state between transactions - balanceOf and totalSupply are contract storage variables that maintain state across calls.
 * 
 * 2. **Multi-Transaction Exploitation**:
 *    - Transaction 1: User calls burn() with legitimate balance
 *    - External call to burnRegistry allows malicious registry to re-enter burn()
 *    - During reentrancy, the original balance check is still satisfied (state not yet updated)
 *    - Multiple reentrant calls can occur before any state changes take effect
 *    - Each reentrant call passes the balance check but accumulates burn amounts
 * 
 * 3. **Exploitation Sequence**:
 *    - Initial: User has 100 tokens, calls burn(50)
 *    - Balance check passes: balanceOf[user] >= 50 ✓
 *    - External call to burnRegistry triggers reentrancy
 *    - Malicious registry calls burn(50) again while original state unchanged
 *    - Second balance check passes: balanceOf[user] still 100 >= 50 ✓
 *    - This can repeat multiple times before any state updates occur
 *    - Finally, all accumulated burns execute: user burns 150+ tokens with only 100 balance
 * 
 * 4. **Why Multi-Transaction Required**:
 *    - Each reentrant call is technically a separate transaction context
 *    - State changes accumulate across these nested transaction calls
 *    - The vulnerability depends on state not being updated between the external call and final state changes
 *    - A single transaction without external calls cannot exploit this pattern
 * 
 * 5. **Realistic Implementation**: Adding external registry notifications for burn events is a common pattern in DeFi protocols for analytics, governance, or reward distribution, making this vulnerability realistic and subtle.
 */
pragma solidity ^0.4.16;

interface IBurnRegistry {
    function onBurn(address burner, uint256 value) external;
}

contract HARDToken {

    string public name;
    string public symbol;
    uint8 public decimals = 4;

    uint256 public totalSupply;

    address public burnRegistry;
    
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    function HARDToken() public {
        totalSupply = 600000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "HARD Coin";
        symbol = "HARD";
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

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }
     
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
     
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }
     
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external burn registry before state updates
        if (burnRegistry != address(0)) {
            IBurnRegistry(burnRegistry).onBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                      
        Burn(msg.sender, _value);
        return true;
    }
     
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        Burn(_from, _value);
        return true;
    }
}
