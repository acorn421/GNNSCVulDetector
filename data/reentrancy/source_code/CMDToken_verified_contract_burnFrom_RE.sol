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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the token holder before state updates. This creates a classic reentrancy scenario where:
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. **Transaction 1**: Attacker sets up by approving themselves a large allowance on a malicious contract
 * 2. **Transaction 2**: Attacker calls burnFrom() targeting the malicious contract
 * 3. **During Transaction 2**: The external callback to the malicious contract triggers before state updates
 * 4. **Reentrancy Attack**: Malicious contract re-enters burnFrom() or calls approve() to manipulate allowances
 * 5. **State Accumulation**: Multiple reentrant calls can drain more tokens than originally allowed
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires prior setup (approve transactions) to establish allowances
 * - The attack leverages the persistent state of allowance mappings across transactions
 * - Multiple calls accumulate state changes that wouldn't be possible in a single atomic transaction
 * - The external call creates a window for state manipulation between transactions
 * 
 * **Stateful Nature:**
 * - Exploits the persistent allowance state set in previous transactions
 * - Each reentrant call can modify allowance state that affects subsequent calls
 * - The vulnerability compounds across multiple transaction executions
 * 
 * This creates a realistic reentrancy vulnerability that requires sophisticated multi-transaction exploitation patterns, making it ideal for security research and analysis.
 */
pragma solidity ^0.4.16;

contract CMDToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    constructor() public {
        totalSupply = 200000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "CloudMind";
        symbol = "CMD";
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
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                      
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                
        require(_value <= allowance[_from][msg.sender]);    
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the token holder about the burn operation
        // This external call occurs before state updates, creating reentrancy opportunity
        if(_from != msg.sender && _from.delegatecall.gas(2300)(bytes4(keccak256("onTokenBurn(address,uint256)")), msg.sender, _value)) {
            // Continue regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }
}
