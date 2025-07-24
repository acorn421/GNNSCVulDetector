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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn notification contract before state updates. This creates a classic reentrancy attack vector where:
 * 
 * 1. **Multi-Transaction Setup**: An attacker needs to first set up their malicious contract as the burnNotificationContract (through a separate transaction/function call)
 * 
 * 2. **State Persistence**: The vulnerability depends on the persistent state of burnNotificationContract being set to the attacker's contract address
 * 
 * 3. **Exploitation Sequence**:
 *    - Transaction 1: Attacker sets burnNotificationContract to their malicious contract
 *    - Transaction 2: Attacker calls burn() which triggers their onBurn() callback
 *    - During the callback, the attacker can re-enter burn() again before the original balance update occurs
 *    - This allows burning more tokens than the attacker actually owns
 * 
 * 4. **Multi-Transaction Dependency**: The vulnerability cannot be exploited in a single transaction because:
 *    - The attacker must first establish their malicious contract address in the system state
 *    - The actual exploitation then occurs in subsequent burn() calls
 *    - The vulnerability depends on the accumulated state from previous transactions
 * 
 * 5. **Realistic Implementation**: This pattern is commonly seen in production contracts where external notifications or integrations are added for legitimate business purposes (tracking burns, updating external systems, etc.)
 * 
 * The vulnerability is stateful because it depends on the persistent burnNotificationContract state variable and requires multiple transactions to both set up and exploit the reentrancy condition.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

interface BurnNotifier {
    function onBurn(address _from, uint256 _value) external;
}

contract HealthCoin {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    
    address public burnNotificationContract;

    constructor(
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
    
    // Allow contract owner to set the burn notification contract address
    function setBurnNotificationContract(address _addr) public {
        burnNotificationContract = _addr;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external burn notification contract before state update
        if (burnNotificationContract != address(0)) {
            BurnNotifier(burnNotificationContract).onBurn(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
}
