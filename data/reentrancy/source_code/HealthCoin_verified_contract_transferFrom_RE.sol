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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating the allowance state. This creates a classic reentrancy vulnerability where:
 * 
 * 1. **Multi-Transaction Setup**: An attacker must first obtain allowance through approve() calls in separate transactions
 * 2. **Stateful Exploitation**: The vulnerability exploits the persistent allowance state across multiple transferFrom calls
 * 3. **Reentrancy Window**: The external call to onTokenReceive() happens before allowance is decremented, allowing the recipient contract to re-enter transferFrom
 * 4. **State Accumulation**: Each successful re-entry can drain more tokens than the original allowance should permit, requiring multiple nested calls to maximize damage
 * 
 * The vulnerability requires multiple transactions because:
 * - Initial setup transactions are needed to establish allowances
 * - The exploit itself involves multiple nested calls during the reentrancy attack
 * - The attack leverages state that persists between transaction boundaries (allowance mapping)
 * - Maximum exploitation requires careful orchestration across multiple transaction contexts
 * 
 * This follows real-world patterns seen in token contracts that implement transfer hooks or notifications, making it a realistic and subtle vulnerability that could appear in production code.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract HealthCoin {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function HealthCoin(
        uint256 initialSupply
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "HealthCoin"; 
        symbol = "HCoin";
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Check if recipient is a contract and notify it about the incoming transfer
        uint length;
        assembly { length := extcodesize(_to) }
        if (length > 0) {
            // External call before state update - creates reentrancy window
            _to.call(abi.encodeWithSignature("onTokenReceive(address,address,uint256)", _from, _to, _value));
            // Continue regardless of callback success for compatibility
        }
        
        // State update happens after external call - vulnerability window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
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