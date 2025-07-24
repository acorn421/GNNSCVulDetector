/*
 * ===== SmartInject Injection Details =====
 * Function      : frozen
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the target address about the freeze operation. The vulnerability is multi-transaction because:
 * 
 * 1. **Transaction 1**: An attacker (who is the owner) calls frozen() on a malicious contract address they control. The external call to targetAddress.call() creates a reentrancy window where the malicious contract can call back into the frozen() function.
 * 
 * 2. **Transaction 2+**: During the external call, the malicious contract can re-enter the frozen() function multiple times before the original state updates are completed. Since the initial require() checks pass but state updates haven't happened yet, the attacker can freeze more tokens than available.
 * 
 * 3. **State Accumulation**: Each reentrancy call accumulates frozen tokens while the available balance hasn't been properly decremented yet, allowing the attacker to freeze tokens that don't exist or belong to other users.
 * 
 * The vulnerability requires multiple function calls because:
 * - The initial call sets up the reentrancy opportunity
 * - The callback creates additional state modifications
 * - The final state check happens after all reentrancy calls complete
 * - The attacker needs to deploy a malicious contract first, then call frozen() on it
 * 
 * This creates a realistic scenario where an admin function includes a "helpful" notification mechanism that introduces a critical security flaw through the timing of external calls relative to state updates.
 */
pragma solidity ^0.4.16;
//pragma experimental ABIEncoderV2;

contract HgcToken {

    string public name = "Hello Hello Coins";
    string public symbol = "ZZZHHC";
    uint256 public decimals = 6;

    uint256 constant initSupplyUnits = 21000000000000000;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    address owner = 0x0;

    struct Account{
        uint256 available;
        uint256 frozen;
    }

    mapping (address => Account) public accounts;
    mapping (address => mapping (address => uint256)) public allowance;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    function HgcToken() public {
        owner = msg.sender ;
        totalSupply = initSupplyUnits;

        Account memory account = Account({
            available:totalSupply,
            frozen:0
            });

        accounts[owner] = account;
        emit Transfer(0x0, owner, initSupplyUnits);
    }

    function totalSupply() public constant returns (uint256 supply) {
        return totalSupply;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance){
        return balanceFor(accounts[_owner]);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        Account storage accountFrom = accounts[msg.sender] ;
        require(accountFrom.available >= _value);

        Account storage accountTo = accounts[_to] ;
        uint256 count = balanceFor(accountFrom) + balanceFor(accountTo) ;
        require(accountTo.available + _value >= accountTo.available);

        accountFrom.available -= _value;
        accountTo.available += _value;

        require(count == balanceFor(accountFrom) + balanceFor(accountTo)) ;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        Account storage accountFrom = accounts[_from] ;
        require(accountFrom.available >= _value);

        Account storage accountTo = accounts[_to] ;
        require(accountTo.available + _value >= accountTo.available);
        require(allowance[_from][msg.sender] >= _value);

        uint256 count = balanceFor(accountFrom) + balanceFor(accountTo) ;

        accountTo.available += _value;
        accountFrom.available -= _value;

        allowance[_from][msg.sender] -= _value;

        require(count == balanceFor(accountFrom) + balanceFor(accountTo)) ;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function balanceFor(Account box) internal pure returns (uint256 balance){
        return box.available + box.frozen ;
    }

    function stop() public isOwner isRunning{
        stopped = true;
    }

    function start() public isOwner {
        stopped = false;
    }

    function setName(string _name) public isOwner {
        name = _name;
    }

    function burn(uint256 _value) public isRunning {
        Account storage account = accounts[msg.sender];
        require(account.available >= _value);
        account.available -= _value ;

        Account storage systemAccount = accounts[0x0] ;
        systemAccount.available += _value;

        emit Transfer(msg.sender, 0x0, _value);
    }

    function frozen(address targetAddress , uint256 value) public isOwner returns (bool success){
        Account storage account = accounts[targetAddress];

        require(value > 0 && account.available >= value);

        uint256 count = account.available + account.frozen;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Add external call before state update to notify target about freeze
        if (targetAddress != 0x0) {
            // External call to notify target address about freezing - creates reentrancy window
            (bool callSuccess, ) = targetAddress.call(abi.encodeWithSignature("onFreezeNotification(uint256)", value));
            // Continue execution regardless of external call result
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        account.available -= value;
        account.frozen += value;

        require(count == account.available + account.frozen);

        return true;
    }

    function unfrozen(address targetAddress, uint256 value) public isOwner returns (bool success){
        Account storage account = accounts[targetAddress];

        require(value > 0 && account.frozen >= value);

        uint256 count = account.available + account.frozen;

        account.available += value;
        account.frozen -= value;

        require(count == account.available + account.frozen);

        return true;
    }

    function accountOf(address targetAddress) public isOwner constant returns (uint256 available, uint256 locked){
        Account storage account = accounts[targetAddress];
        return (account.available, account.frozen);
    }

    function accountOf() public constant returns (uint256 available, uint256 locked){
        Account storage account = accounts[msg.sender];
        return (account.available, account.frozen);
    }

    function kill() public isOwner {
        selfdestruct(owner);
    }

}