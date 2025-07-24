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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Setup Phase (Transaction 1)**: Attacker deploys a malicious contract that implements onTokenReceived() and approves allowances for the victim account.
 * 
 * 2. **Initial Attack (Transaction 2)**: Attacker calls transferFrom() to transfer tokens to their malicious contract. During the external call to onTokenReceived(), the malicious contract can:
 *    - Call transferFrom() again with the same allowance (reentrancy)
 *    - The allowance hasn't been decremented yet, so the check passes
 *    - Multiple transfers can occur using the same allowance
 * 
 * 3. **State Persistence**: The persistent state (accounts mapping and allowance mapping) allows the exploit to work across multiple nested calls and transactions.
 * 
 * **Why Multi-Transaction:**
 * - The vulnerability relies on accumulated allowance state from previous transactions
 * - Multiple nested calls within the same transaction exploit the delayed state updates
 * - The attacker needs to set up allowances in separate transactions before exploitation
 * - Each reentrant call leverages the persistent state that hasn't been updated yet
 * 
 * **Key Vulnerability Points:**
 * - External call occurs before state changes (violates checks-effects-interactions)
 * - Allowance is only decremented after the external call
 * - No reentrancy guard protection
 * - State persists between calls, enabling multi-transaction exploitation patterns
 * 
 * This creates a realistic reentrancy vulnerability where an attacker can drain funds by exploiting the window between the external call and state updates, with the exploitation requiring multiple transaction steps to set up and execute.
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

    constructor() public {
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

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool) {
        Account storage accountFrom = accounts[_from] ;
        require(accountFrom.available >= _value);

        Account storage accountTo = accounts[_to] ;
        require(accountTo.available + _value >= accountTo.available);
        require(allowance[_from][msg.sender] >= _value);

        uint256 count = balanceFor(accountFrom) + balanceFor(accountTo) ;

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to recipient before state changes - Creates reentrancy window
        if (isContract(_to)) {
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // Continue execution regardless of call success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        accountTo.available += _value;
        accountFrom.available -= _value;

        allowance[_from][msg.sender] -= _value;

        require(count == balanceFor(accountFrom) + balanceFor(accountTo)) ;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
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
