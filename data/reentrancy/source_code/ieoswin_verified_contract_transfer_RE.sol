/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before balance updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Key Changes Made:**
 * 1. Added external call to `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))` before balance updates
 * 2. Placed the external call after balance validation but before state modifications
 * 3. Added check `if (_to.code.length > 0)` to only call contracts, making it realistic
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious contract with `onTokenReceived` function
 * 2. **Transaction 2**: Victim calls `transfer()` to send tokens to attacker's contract
 * 3. **During Transaction 2**: The external call triggers attacker's `onTokenReceived`, which can:
 *    - Re-enter the `transfer` function while balances are not yet updated
 *    - Call other functions like `approve` or `transferFrom` while the contract is in inconsistent state
 *    - Use the intermediate state where balance checks passed but updates haven't occurred
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker must first deploy and set up the malicious contract (Transaction 1)
 * - The vulnerability only activates when tokens are sent to a contract address (Transaction 2)
 * - The reentrancy exploits the state window between balance validation and balance updates
 * - Cross-function reentrancy can be used to manipulate allowances while transfer is in progress
 * 
 * **State Persistence:**
 * - The malicious contract remains deployed between transactions
 * - Balance states persist and can be manipulated across multiple function calls
 * - The vulnerability can be triggered multiple times as the malicious contract remains active
 * 
 * This creates a realistic reentrancy vulnerability that requires careful orchestration across multiple transactions, making it a sophisticated stateful attack vector.
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
            revert("Wallet Locked");
        }

        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient before balance update (vulnerable to reentrancy)
        if (extcodesize(_to) > 0) {
            // Variable rename to avoid shadowing, use callSuccess instead of success
            bool callSuccess = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue even if call fails
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }

    // extcodesize helper function for Solidity 0.4.x
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
