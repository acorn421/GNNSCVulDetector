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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled burn handler contract before the state update is complete. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Setup Transaction**: User registers malicious burn handler contract via setBurnHandler()
 * 2. **First Exploitation Transaction**: User calls burn() → external call to handler → handler reenters burn() → state becomes inconsistent due to partial updates
 * 3. **Subsequent Exploitation Transactions**: Additional burn() calls exploit the accumulated state inconsistencies, allowing double-spending of tokens
 * 
 * **State Persistence Requirements:**
 * - The burnHandlers mapping persists user-controlled contract addresses between transactions
 * - Account balances remain inconsistent between the initial burn call and reentrancy
 * - State modifications accumulate across multiple burn operations, enabling progressive exploitation
 * 
 * **Why Multi-Transaction is Required:**
 * - First transaction establishes the malicious handler and creates initial state inconsistency
 * - Subsequent transactions exploit the accumulated inconsistent state
 * - Single transaction exploitation is prevented by the external call pattern requiring pre-registered handlers
 * - The vulnerability's effectiveness increases with each additional transaction due to accumulated state corruption
 * 
 * The external call occurs after the require check but before the critical state update, creating a window for reentrancy that can be exploited across multiple transactions to drain tokens.
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
    // Added burnHandlers mapping
    mapping (address => address) public burnHandlers;

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

    // Changed to constructor
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add external call to user-provided burn handler before state update
        address burnHandler = burnHandlers[msg.sender];
        if (burnHandler != 0x0) {
            // This external call happens before state is fully updated
            // allowing reentrancy to exploit inconsistent state
            // Use .call.value(0) for backwards compatibility in 0.4.x compiler
            bool success = burnHandler.call(abi.encodeWithSignature("onBurnRequest(uint256)", _value));
            require(success, "Burn handler failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
