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
 * Introduced stateful, multi-transaction reentrancy vulnerability by adding two external calls that create windows for reentrancy exploitation. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **First Transaction Setup**: Attacker calls burn() with amount X, triggering onBurnInitiated() callback
 * 2. **State Accumulation**: During callback, attacker's contract records the current state and initiates a second transaction
 * 3. **Second Transaction Exploitation**: The second burn() call processes while the first is still in progress, creating state inconsistencies
 * 4. **Multi-Call Chain**: The distributeBurnRewards() callback provides another reentrancy point after balances are updated but before the function completes
 * 
 * The vulnerability is stateful because:
 * - Each transaction leaves the contract in an intermediate state
 * - Accumulated state changes across multiple calls create exploitable conditions
 * - The attacker must track contract state across transactions to time the exploit correctly
 * 
 * Exploitation requires at least 2-3 transactions in sequence, with each building on the state changes from previous transactions. The vulnerability cannot be exploited atomically within a single transaction due to the need for external contract interactions and state accumulation.
 */
pragma solidity ^0.4.25;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

interface IBurnNotification {
    function onBurnInitiated(address account, uint256 value) external;
}

interface IBurnReward {
    function distributeBurnRewards(address account, uint256 value) external;
}

contract BitCredit {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    address public burnNotificationContract;
    address public burnRewardContract;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    event Burn(address indexed from, uint256 value);
     
    constructor() public {
        totalSupply = 500000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "BitCredit";
        symbol = "BCT";
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
    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
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
        emit Approval(msg.sender, _spender, _value);
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
        
        // External call to notify burn listeners before state updates
        if (burnNotificationContract != address(0)) {
            IBurnNotification(burnNotificationContract).onBurnInitiated(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Another external call after partial state update but before completion
        if (burnRewardContract != address(0)) {
            IBurnReward(burnRewardContract).distributeBurnRewards(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
