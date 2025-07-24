/*
 * ===== SmartInject Injection Details =====
 * Function      : crowdsaleSetup
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Dependencies**: Introduced two external calls to `priceOracleAddr` and `adminNotificationAddr` contracts that can trigger reentrancy.
 * 
 * 2. **Violated Checks-Effects-Interactions Pattern**: Set `marketSupply` before external calls while leaving `marketPrice` to be set after, creating an inconsistent state window.
 * 
 * 3. **Multi-Transaction Exploitation Vector**: 
 *    - **Transaction 1**: Admin calls `crowdsaleSetup()` → `marketSupply` is set → external call triggers reentrancy → attacker calls `purchase()` with old `marketPrice` (still 0 or previous value) while `marketSupply` is already updated
 *    - **Transaction 2**: Attacker can continue exploiting during the external call window before `marketPrice` is finalized
 *    - **Transaction 3**: Setup completes, but damage is done through accumulated state manipulation
 * 
 * 4. **Stateful Persistence**: The vulnerability requires state changes (`marketSupply` update) to persist between transactions, making it impossible to exploit in a single atomic transaction.
 * 
 * 5. **Realistic Integration**: Adding external calls for price validation and admin notifications fits naturally within crowdsale setup functionality.
 * 
 * **Multi-Transaction Exploitation Mechanism**:
 * - The vulnerability requires the setup process to span multiple transactions due to reentrant calls
 * - Attackers exploit the inconsistent state where `marketSupply` is set but `marketPrice` is not yet finalized
 * - Each reentrant call can potentially trigger `purchase()` function with favorable conditions
 * - The exploit accumulates value across multiple transactions during the setup window
 * 
 * **Why Multi-Transaction is Required**:
 * - The vulnerability cannot be exploited in a single transaction because it requires the external contracts to trigger reentrancy
 * - State changes must persist between the initial setup call and the reentrant exploitation calls
 * - The attack relies on the time window between state updates, which spans multiple transaction contexts
 */
pragma solidity ^0.4.16;

contract airDrop {
    function verify(address _address, bytes32 _secret) public constant returns (bool _status);
}

interface IPriceOracle {
    function validatePrice(uint _perEther) external;
}

interface IAdminNotification {
    function notifySetup(uint tempSupply, uint tempPrice) external;
}

contract BitcoinQuick {
    string public constant symbol = "BTCQ";

    string public constant name = "Bitcoin Quick";

    uint public constant decimals = 8;

    uint _totalSupply = 21000000 * 10 ** decimals;

    uint public marketSupply;

    uint public marketPrice;

    address owner;

    address airDropVerify;

    uint public airDropAmount;

    uint32 public airDropHeight;

    mapping (address => bool) public airDropMembers;

    mapping (address => uint) accounts;

    mapping (address => mapping (address => uint)) allowed;

    // Added declarations for the missing variables
    address public priceOracleAddr;
    address public adminNotificationAddr;

    event Transfer(address indexed _from, address indexed _to, uint _value);

    event Approval(address indexed _owner, address indexed _spender, uint _value);

    // Use constructor keyword as per pragma ^0.4.16
    function BitcoinQuick() public {
        owner = msg.sender;
        accounts[owner] = _totalSupply;
        Transfer(address(0), owner, _totalSupply);
    }

    function totalSupply() public constant returns (uint __totalSupply) {
        return _totalSupply;
    }

    function balanceOf(address _account) public constant returns (uint balance) {
        return accounts[_account];
    }

    function allowance(address _account, address _spender) public constant returns (uint remaining) {
        return allowed[_account][_spender];
    }

    function transfer(address _to, uint _amount) public returns (bool success) {
        require(_amount > 0 && accounts[msg.sender] >= _amount);
        accounts[msg.sender] -= _amount;
        accounts[_to] += _amount;
        Transfer(msg.sender, _to, _amount);
        return true;
    }

    function transferFrom(address _from, address _to, uint _amount) public returns (bool success) {
        require(_amount > 0 && accounts[_from] >= _amount && allowed[_from][msg.sender] >= _amount);
        accounts[_from] -= _amount;
        allowed[_from][msg.sender] -= _amount;
        accounts[_to] += _amount;
        Transfer(_from, _to, _amount);
        return true;
    }

    function approve(address _spender, uint _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }

    function purchase() public payable returns (bool _status) {
        require(msg.value > 0 && marketSupply > 0 && marketPrice > 0 && accounts[owner] > 0);
        // Calculate available and required units
        uint unitsAvailable = accounts[owner] < marketSupply ? accounts[owner] : marketSupply;
        uint unitsRequired = msg.value / marketPrice;
        uint unitsFinal = unitsAvailable < unitsRequired ? unitsAvailable : unitsRequired;
        // Transfer funds
        marketSupply -= unitsFinal;
        accounts[owner] -= unitsFinal;
        accounts[msg.sender] += unitsFinal;
        Transfer(owner, msg.sender, unitsFinal);
        // Calculate remaining ether amount
        uint remainEther = msg.value - (unitsFinal * marketPrice);
        // Return extra ETH to sender
        if (remainEther > 0) {
            msg.sender.transfer(remainEther);
        }
        return true;
    }

    function airDropJoin(bytes32 _secret) public payable returns (bool _status) {
        // Checkout airdrop conditions and eligibility
        require(!airDropMembers[msg.sender] && airDrop(airDropVerify).verify(msg.sender, _secret) && airDropHeight > 0 && airDropAmount > 0 && accounts[owner] >= airDropAmount);
        // Transfer amount
        accounts[owner] -= airDropAmount;
        accounts[msg.sender] += airDropAmount;
        airDropMembers[msg.sender] = true;
        Transfer(owner, msg.sender, airDropAmount);
        airDropHeight--;
        // Return extra amount to sender
        if (msg.value > 0) {
            msg.sender.transfer(msg.value);
        }
        return true;
    }

    function airDropSetup(address _contract, uint32 _height, uint _units) public returns (bool _status) {
        require(msg.sender == owner);
        airDropVerify = _contract;
        airDropHeight = _height;
        airDropAmount = _units * 10 ** decimals;
        return true;
    }

    function crowdsaleSetup(uint _supply, uint _perEther) public returns (bool _status) {
        require(msg.sender == owner && accounts[owner] >= _supply * 10 ** decimals);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Set temporary values before external validation
        uint tempSupply = _supply * 10 ** decimals;
        uint tempPrice = 1 ether / (_perEther * 10 ** decimals);
        
        // Update state early to enable multi-transaction exploitation
        marketSupply = tempSupply;
        
        // External call for price oracle validation - creates reentrancy opportunity
        if (priceOracleAddr != address(0)) {
            IPriceOracle(priceOracleAddr).validatePrice(_perEther);
        }
        
        // External call for admin notification - second reentrancy vector
        if (adminNotificationAddr != address(0)) {
            IAdminNotification(adminNotificationAddr).notifySetup(tempSupply, tempPrice);
        }
        
        // Complete state update after external calls (vulnerable pattern)
        marketPrice = tempPrice;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    function withdrawFunds(uint _amount) public returns (bool _status) {
        require(msg.sender == owner && _amount > 0 && this.balance >= _amount);
        owner.transfer(_amount);
        return true;
    }
}
