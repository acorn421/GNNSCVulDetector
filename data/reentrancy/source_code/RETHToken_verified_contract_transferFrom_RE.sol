/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before updating the allowance state. This creates a classic checks-effects-interactions violation where:
 * 
 * 1. **External Call Before State Update**: The recipient contract is notified via `onTokenReceived()` callback BEFORE the allowance is decremented
 * 2. **Stateful Exploitation**: The vulnerability requires building up allowance state across multiple transactions
 * 3. **Multi-Transaction Attack Pattern**:
 *    - Transaction 1: Attacker calls transferFrom() with a malicious recipient contract
 *    - The callback re-enters transferFrom() with the same parameters while allowance is still unchanged
 *    - This creates inconsistent state where the same allowance can be used multiple times
 *    - Transaction 2+: Subsequent legitimate calls operate on corrupted allowance state
 * 
 * The vulnerability is realistic because recipient notification callbacks are common in advanced token implementations. The attack requires multiple transactions because the attacker must first establish the allowance, then exploit the reentrancy window to drain more tokens than allowed, creating persistent state corruption that affects future transactions.
 */
pragma solidity ^0.4.16;

contract RETHToken {

    string public name;
    string public symbol;
    uint8 public decimals = 18;

    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    function RETHToken() public {
        totalSupply = 400000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "RETH Token";
        symbol = "RETH";
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient before state changes - enables reentrancy
        if(isContract(_to)) {
            // This is equivalent to _to.call(...);
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue execution regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }

    // Helper for old compiler: checks if an address is a contract
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
}
