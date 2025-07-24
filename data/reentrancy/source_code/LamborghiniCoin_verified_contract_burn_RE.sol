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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn notification contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `IBurnNotification(burnNotificationContract).notifyBurn(msg.sender, _value)` before balance updates
 * 2. This violates the Checks-Effects-Interactions pattern by placing an external call before state modifications
 * 3. The external call allows the recipient contract to re-enter and manipulate state
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `burn()` with a legitimate value
 * 2. **During Transaction 1**: The external call to `notifyBurn()` is made while balances are still unchanged
 * 3. **In the callback**: The malicious notification contract can call other functions or set up conditions for future exploitation
 * 4. **Transaction 2+**: Attacker exploits the state inconsistency created by the reentrancy, potentially calling burn again before the first burn completes its state updates
 * 
 * **Why Multiple Transactions are Required:**
 * - The vulnerability creates a window where external contracts can observe and react to burn operations before state changes are finalized
 * - Attackers must first establish the notification contract and then exploit the timing window across multiple burn calls
 * - The stateful nature allows accumulation of exploitable conditions that persist between transactions
 * - The notification mechanism creates persistent state dependencies that enable cross-transaction exploitation
 * 
 * **Note**: This assumes the contract would also need additional state variables like `address public burnNotificationContract` and interface definition for `IBurnNotification` to be fully functional.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

// Declaring the burn notification interface for notifyBurn
interface IBurnNotification {
    function notifyBurn(address burner, uint256 value) external;
}

contract LamborghiniCoin {
    string public name = "Lamborghini Official Coin"; //Implemented by Nando AEC 2018-05-22
    string public symbol = "LOCC";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    // Added burn notification contract variable
    address public burnNotificationContract;

    constructor(
                ) public {
        totalSupply = 200000000 * 10 ** uint256(18);  
        balanceOf[msg.sender] = totalSupply;         
        name = "Lamborghini Official Coin";           
        symbol = "LOCC";                               
    }

    /**
     * Internal transfer, only can be called by this contract
     */
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

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call before state updates - vulnerable to reentrancy
        if (burnNotificationContract != address(0)) {
            IBurnNotification(burnNotificationContract).notifyBurn(msg.sender, _value);
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
