/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to a burn notification contract between the user's balance deduction and the completion of the burn state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1:** The attacker deploys a malicious contract that implements IBurnNotification and sets it as the burnNotificationContract (this would require owner privileges or separate vulnerability).
 * 
 * **Transaction 2+:** The attacker calls burn() with their tokens. During the onBurn callback, the malicious contract can re-enter the burn function. Since the user's balance has already been reduced but the burn tracking (balanceOf[0x0]) hasn't been updated yet, the malicious contract can:
 * 1. Check that balanceOf[0x0] hasn't been updated yet
 * 2. Perform additional burns or manipulate state
 * 3. Potentially extract value through the timing difference
 * 
 * **Multi-Transaction Nature:**
 * - Requires initial setup of the malicious notification contract
 * - Requires the notification contract to be registered with the token contract
 * - The vulnerability depends on accumulated state changes across multiple burn operations
 * - Each burn call builds upon the previous state, making multiple burns with a single balance deduction possible
 * 
 * **Exploitation Sequence:**
 * 1. Deploy malicious IBurnNotification contract
 * 2. Register it as burnNotificationContract (requires separate transaction)
 * 3. Call burn() - triggers onBurn callback during incomplete state transition
 * 4. In callback, can call burn() again or manipulate other functions while balanceOf[0x0] is stale
 * 5. Repeat across multiple transactions to accumulate the vulnerability effects
 * 
 * This creates a realistic burn notification feature that violates the Checks-Effects-Interactions pattern, making it vulnerable to reentrancy attacks that require multiple transactions to set up and exploit.
 */
pragma solidity ^0.4.22;

contract ieoswin {

    string public name = "ieos win";
    string public symbol = "ieow";
    uint256 public decimals = 18;
    address public adminWallet;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public totalSupply = 80000000;
    bool public stopped = false;
    uint public constant TOKEN_SUPPLY_TOTAL = 80000000000000000000000000;
    uint256 constant valueFounder = TOKEN_SUPPLY_TOTAL;
    address owner = 0x0;

    mapping (address => bool) public LockWallets;

    // ===== Added missing declarations for compilation =====
    address public burnNotificationContract;

    // Interface for burn notification contract
    // NOTE: In Solidity 0.4.x interfaces must be outside contract scope
}

interface IBurnNotification {
    function onBurn(address from, uint256 value) external;
}

contract ieoswin2 is ieoswin {
    function lockWallet(address _wallet) public isOwner{
        LockWallets[_wallet]=true;
    }

    function unlockWallet(address _wallet) public isOwner{
        LockWallets[_wallet]=false;
    }

    function containsLock(address _wallet) public view returns (bool){
        return LockWallets[_wallet];
    }

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert(!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    constructor() public {
        owner = msg.sender;
        adminWallet = owner;
        totalSupply = valueFounder;
        balanceOf[owner] = valueFounder;
        emit Transfer(0x0, owner, valueFounder);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        if (containsLock(msg.sender) == true) {
            revert("Wallet Locked");
        }

        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {

        if (containsLock(_from) == true) {
            revert("Wallet Locked");
        }

        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() public isOwner {
        stopped = true;
    }

    function start() public isOwner {
        stopped = false;
    }

    function setName(string _name) public isOwner {
        name = _name;
    }

    function setSymbol(string _symbol) public isOwner {
        symbol = _symbol;
    }

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to burn notification contract before completing all state updates
        if (burnNotificationContract != address(0)) {
            IBurnNotification(burnNotificationContract).onBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
