/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after state updates. The vulnerability exploits the fact that balances are updated before the external call, but the function continues executing after the call. This creates a window where:
 * 
 * 1. **Transaction 1**: Attacker calls transfer() to a malicious contract
 * 2. **During external call**: Malicious contract receives onTokenReceived() callback
 * 3. **Reentrant call**: Malicious contract calls transfer() again while original transaction is still executing
 * 4. **State exploitation**: The reentrant call sees updated balances from the first call, allowing progressive fund drainage
 * 
 * The vulnerability requires multiple transactions because:
 * - Each transfer() call updates persistent balance state
 * - The external call creates a reentrancy window where the attacker can call back
 * - Multiple sequential calls are needed to drain funds progressively
 * - The attacker must build up state across multiple transactions to maximize extraction
 * 
 * This follows the checks-effects-interactions pattern violation where the external interaction happens after state changes but before function completion, creating a classic reentrancy vulnerability that requires accumulated state exploitation across multiple calls.
 */
pragma solidity ^0.4.25;

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b > 0);
        uint256 c = a / b;
        assert(a == b * c);
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a - b;
        assert(b <= a);
        assert(a == c + b);
        return c;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        assert(a == c - b);
        return c;
    }
}

contract owned {
    address public owner;
    
    constructor() public{
        owner = msg.sender;
    }
    
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    
    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}

contract EducationTokens is owned{
    using SafeMath for uint256;

    bool private transferFlag;
    string public name;
    uint256 public decimals;
    string public symbol;
    string public version;
    uint256 public totalSupply;
    uint256 public deployTime;

    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowed;
    mapping(address => uint256) private userLockedTokens;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Lock(address userAddress, uint256 amount);
    event Unlock(address userAddress,uint256 amount);
    event SetFlag(bool flag);

    //constructor(string tokenName, string tokenSymbol) public {
    constructor() public {
        transferFlag = true;
        //name = tokenName;
        name = "sniperyao";
        decimals = 4;
        //symbol = tokenSymbol;
        symbol = "sy";
        version = "V1.0";
        totalSupply = 2100000000 * 10 ** decimals;
        owner = msg.sender;
        deployTime = block.timestamp;
        
        balances[msg.sender] = totalSupply;
    }
    
    modifier canTransfer() {
        require(transferFlag);
        _;
    }
    
    function name()constant public returns (string token_name){
        return name;
    }
    
    function symbol() constant public returns (string _symbol){
        return symbol;
    }
    
    function decimals() constant public returns (uint256 _decimals){
        return decimals;
    }
    
    function totalSupply() constant public returns (uint256 _totalSupply){
        return totalSupply;
    }
    
    function setTransferFlag(bool transfer_flag) public onlyOwner{
        transferFlag = transfer_flag;
        emit SetFlag(transferFlag);
    }
    
    function tokenLock(address _userAddress, uint256 _amount) public onlyOwner {
        require(balanceOf(_userAddress) >= _amount);
        userLockedTokens[_userAddress] = userLockedTokens[_userAddress].add(_amount);
        emit Lock(_userAddress, _amount);
    }

    function tokenUnlock(address _userAddress, uint256 _amount) public onlyOwner {
        require(userLockedTokens[_userAddress] >= _amount);
        userLockedTokens[_userAddress] = userLockedTokens[_userAddress].sub(_amount);
        emit Unlock(_userAddress, _amount);
    }

    function balanceOf(address _owner) view public returns (uint256 balance) {
        return balances[_owner] - userLockedTokens[_owner];
    }
    
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
    
    function transfer(address _to, uint256 _value) public canTransfer returns (bool success) {
        require(balanceOf(msg.sender) >= _value);
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract about incoming tokens (vulnerable external call)
        if (_to != address(0) && isContract(_to)) {
            // External call to recipient contract - creates reentrancy opportunity
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue execution regardless of call result to maintain functionality
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public canTransfer returns (bool success) {
        require(balanceOf(_from) >= _value && allowed[_from][msg.sender] >= _value);
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant public returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
