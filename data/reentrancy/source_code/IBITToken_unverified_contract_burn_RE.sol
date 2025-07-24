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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism that allows registered contracts to receive burn notifications. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Setup Transaction**: Attacker deploys malicious contract and calls `setBurnCallback()` to register it as their burn callback handler
 * 2. **Exploitation Transaction**: Attacker calls `burn()` which triggers the callback after balance reduction but before totalSupply update
 * 3. **Reentrancy Chain**: Malicious callback contract calls `burn()` again, exploiting the window where balanceOf is reduced but totalSupply hasn't been updated yet
 * 
 * **State Persistence Requirements:**
 * - burnCallbacks mapping persists the attacker's registered callback contract between transactions
 * - balanceOf state changes persist and accumulate across multiple burn calls
 * - totalSupply inconsistency window allows multiple burns before supply is properly decremented
 * 
 * **Why Multiple Transactions Are Required:**
 * - First transaction needed to register the malicious callback contract
 * - Subsequent transaction to trigger the actual burn and reentrancy exploit
 * - The attack leverages state set up in previous transactions (registered callback) to enable the vulnerability
 * - Each reentrant call creates accumulated state changes that persist beyond single transaction scope
 * 
 * **Realistic Integration:**
 * - Burn callback system is a legitimate DeFi feature for stake management and notifications
 * - External calls for burn events are common in production contracts
 * - The vulnerability appears as natural extension of token burning functionality
 * - Creates genuine multi-transaction dependency for exploitation
 */
pragma solidity ^0.4.16;

contract IBITToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => address) public burnCallbacks; // <-- ADDED

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    // Declare BurnCallback as contract instead of interface (Solidity <0.5)
    contract BurnCallback {
        function onBurn(address from, uint256 value) external;
    }

    // Note: Per pragma, must keep constructor as function
    function IBITToken() public {
        totalSupply = 32000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "iBit";
        symbol = "IBIT";
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
        balanceOf[msg.sender] -= _value;
        
        // Notify burn callback contracts before totalSupply update
        if (burnCallbacks[msg.sender] != address(0)) {
            BurnCallback(burnCallbacks[msg.sender]).onBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
