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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced `burnRequests` mapping to track pending burn operations, creating persistent state between transactions.
 * 
 * 2. **External Call Before State Updates**: Added `notifyBurn` callback to external contract after initial checks but before critical state updates (balance, allowance, totalSupply), violating the checks-effects-interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Path**: 
 *    - **Transaction 1**: Attacker calls burnFrom, which updates burnRequests but then triggers external callback
 *    - **Callback Reentrancy**: Malicious notification contract re-enters burnFrom with different parameters
 *    - **Transaction 2**: Second burnFrom call sees outdated state (balance/allowance not yet updated from first call) but new burnRequests tracking
 *    - **State Manipulation**: Attacker can exploit the window between state reads and updates across multiple transactions
 * 
 * 4. **Stateful Vulnerability**: The burnRequests mapping persists between transactions, allowing attackers to accumulate burn requests and exploit the timing between state checks and updates.
 * 
 * 5. **Realistic Implementation**: The burn notification system is a legitimate feature that could exist in production for DeFi integration, compliance tracking, or user notifications.
 * 
 * **Multi-Transaction Exploitation**:
 * - Requires at least 2 transactions: initial burnFrom call + reentrant callback execution
 * - Exploits state inconsistency between burnRequests tracking and actual balance/allowance updates
 * - Attacker can potentially burn more tokens than allowance permits by exploiting the reentrancy window
 * - The vulnerability becomes more severe with accumulated burnRequests across multiple transactions
 * 
 * **Required Additional Contract Elements** (assumed to exist):
 * ```solidity
 * mapping(address => mapping(address => uint256)) public burnRequests;
 * address public burnNotificationContract;
 * interface IBurnNotification {
 *     function notifyBurn(address from, address spender, uint256 value) external;
 * }
 * ```
 */
pragma solidity ^0.4.13; 

contract owned {
    address public owner;
    function owned() public {
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
contract tokenRecipient {
     function receiveApproval(address from, uint256 value, address token, bytes extraData) public; 
}

interface IBurnNotification {
    function notifyBurn(address from, address by, uint256 value) external;
}

contract token {
    /*Public variables of the token */
    string public name; string public symbol; uint8 public decimals; uint256 public totalSupply;
    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // ===== SMARTINJECT: for vulnerability support START =====
    mapping(address => mapping(address => uint256)) public burnRequests;
    address public burnNotificationContract;
    // ===== SMARTINJECT: for vulnerability support END =====

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
    /* Initializes contract with initial supply tokens to the creator of the contract */
    function token() public {
        balanceOf[msg.sender] = 10000000000000000; 
        totalSupply = 10000000000000000; 
        name = "BCB"; 
        symbol =  "฿";
        decimals = 8; 
    }
    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0); 
        require (balanceOf[_from] > _value); 
        require (balanceOf[_to] + _value > balanceOf[_to]); 
        balanceOf[_from] -= _value; 
        balanceOf[_to] += _value; 
        Transfer(_from, _to, _value);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require (_value < allowance[_from][msg.sender]); 
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value)
        public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }
    /// @notice Remove `_value` tokens from the system irreversibly
    /// @param _value the amount of money to burn
    function burn(uint256 _value) public returns (bool success) {
        require (balanceOf[msg.sender] > _value); // Check if the sender has enough
        balanceOf[msg.sender] -= _value; // Subtract from the sender
        totalSupply -= _value; // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value); // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]); // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track burn requests for notification system
        burnRequests[_from][msg.sender] += _value;
        
        // Notify external burn tracker before completing state updates
        if (burnNotificationContract != address(0)) {
            IBurnNotification(burnNotificationContract).notifyBurn(_from, msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value; // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value; // Subtract from the sender's allowance
        totalSupply -= _value; // Update totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear burn request tracking after successful burn
        burnRequests[_from][msg.sender] = 0;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
}

contract BcbToken is owned, token {
    mapping (address => bool) public frozenAccount;
    /* This generates a public event on the blockchain that will notify clients */
    event FrozenFunds(address target, bool frozen);
  

    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0); 
        require(msg.sender != _to);
        require (balanceOf[_from] > _value); // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); 
        require(!frozenAccount[_from]); // Check if sender is frozen
        require(!frozenAccount[_to]); // Check if recipient is frozen
        balanceOf[_from] -= _value; // Subtract from the sender
        balanceOf[_to] += _value; // Add the same to the recipient
        Transfer(_from, _to, _value);
    }

    function freezeAccount(address target, bool freeze) onlyOwner public {
        frozenAccount[target] = freeze;
        FrozenFunds(target, freeze);
    }
}