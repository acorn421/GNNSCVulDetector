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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled burnNotificationContract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `IBurnNotification(burnNotificationContract).notifyBurn(msg.sender, _value)` after the balance check but before state updates
 * 2. The external call occurs while the contract state (balanceOf and totalSupply) has not yet been updated
 * 3. This creates a window where an attacker can re-enter the burn function with stale state
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * - Transaction 1: Attacker calls burn() with a legitimate value → external call triggers → attacker's malicious contract receives notifyBurn() callback → attacker can call burn() again during callback with the same balance still available
 * - Transaction 2+: Attacker continues to exploit the reentrancy window across multiple nested calls, potentially burning more tokens than they actually possess
 * - The vulnerability becomes more severe when combined with other functions that depend on totalSupply or when the attacker accumulates multiple burn operations
 * 
 * **Why Multiple Transactions are Required:**
 * 1. The attacker needs to first set up the burnNotificationContract to point to their malicious contract
 * 2. The exploitation requires the attacker to re-enter the burn function during the external call, which happens across multiple execution contexts
 * 3. The attacker may need to coordinate with other functions or prepare specific state conditions to maximize the exploit impact
 * 4. The vulnerability's effectiveness increases with repeated exploitation across multiple burn operations
 * 
 * The vulnerability is realistic as token contracts often integrate with external registries, DeFi protocols, or notification systems, making this type of external call plausible in production code.
 */
pragma solidity ^0.4.21;

interface IBurnNotification {
    function notifyBurn(address burner, uint256 value) external;
}

contract TKTToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    address public burnNotificationContract;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    constructor() public {
        totalSupply = 500000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "TKTSA";
        symbol = "TKT";
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
        
        // Notify external registry about burn before state update
        if (burnNotificationContract != address(0)) {
            IBurnNotification(burnNotificationContract).notifyBurn(msg.sender, _value);
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
