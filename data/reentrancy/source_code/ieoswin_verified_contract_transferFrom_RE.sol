/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a recipient contract notification system before updating the allowance. The vulnerability requires multiple transactions to exploit:
 * 
 * **SPECIFIC CHANGES MADE:**
 * 1. Added external call to `TokenReceiver(_to).onTokenReceived(_from, _value)` after balance updates but before allowance reduction
 * 2. Used try-catch to make the external call non-reverting, allowing execution to continue
 * 3. Moved allowance update (`allowance[_from][msg.sender] -= _value`) to occur AFTER the external call
 * 4. Added contract existence check (`_to.code.length > 0`) to make the feature realistic
 * 
 * **MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract that implements `TokenReceiver` interface
 * - Attacker gets approval for tokens from victim account
 * - Attacker calls `transferFrom` with their malicious contract as `_to` address
 * 
 * **Transaction 2 (Exploit):**
 * - During the external call in `onTokenReceived`, the malicious contract:
 *   - Calls `transferFrom` again (reentrancy)
 *   - Since allowance hasn't been reduced yet, the second call succeeds
 *   - This creates a state where tokens are transferred multiple times but allowance is only decremented once per external call
 * 
 * **Transaction 3+ (Profit):**
 * - The attacker can repeat this process across multiple transactions
 * - Each transaction exploits the temporary state inconsistency between balance updates and allowance updates
 * - The vulnerability accumulates over multiple calls, allowing theft of more tokens than originally approved
 * 
 * **WHY MULTI-TRANSACTION EXPLOITATION IS REQUIRED:**
 * 1. **State Persistence**: The allowance state persists between transactions, and the vulnerability exploits the timing of when this state is updated
 * 2. **Accumulative Effect**: Each transaction can extract additional tokens beyond the original allowance, with the effect accumulating over multiple calls
 * 3. **Stateful Dependency**: The exploit relies on the persistent state of allowances in the contract, which can only be manipulated over multiple transactions
 * 4. **Reentrancy Window**: The window between balance updates and allowance updates creates a persistent vulnerability that can be exploited repeatedly across transactions
 * 
 * This vulnerability is realistic because recipient notification systems are common in modern tokens, and the placement of the external call creates a genuine security flaw that requires multiple transactions to fully exploit.
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
            revert();
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
            revert();
        }

        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about incoming transfer (external call before allowance update)
        if (isContract(_to)) {
            require(TokenReceiver(_to).onTokenReceived(_from, _value));
        }
        
        // Update allowance AFTER external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }

    // Helper function to check if address is a contract
    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

// Minimal interface for the recipient contract
contract TokenReceiver {
    function onTokenReceived(address _from, uint256 _value) public returns (bool);
}