/*
 * ===== SmartInject Injection Details =====
 * Function      : burnTokens
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a migration registry before state updates. The vulnerability exploits the window between balance validation and balance reset, allowing attackers to manipulate the burning process across multiple transactions. The attack requires: 1) Transaction 1: Initial burnTokens() call triggers external call to attacker's contract, 2) Transaction 2: Attacker's contract calls burnTokens() again before state updates complete, potentially causing double-burning or phase manipulation. The vulnerability is multi-transaction because the attacker needs to first set up their malicious contract as the migration registry, then exploit the reentrancy window in subsequent burn operations.
 */
pragma solidity ^0.4.11;

// ERC20 token interface is implemented only partially.

contract ARIToken {

    /// @dev Constructor
    /// @param _tokenManager Token manager address.
    /// @param _escrow Escrow address.
    function ARIToken(address _tokenManager, address _escrow) public {
        tokenManager = _tokenManager;
        escrow = _escrow;
    }

    /*/
     *  Constants
    /*/

    string public constant name = "ARI Token";
    string public constant symbol = "ARI";
    uint   public constant decimals = 18;

    /*/
     *  Token state
    /*/

    enum Phase {
        Created,
        Running,
        Paused,
        Migrating,
        Migrated
    }

    Phase public currentPhase = Phase.Created;
    uint public totalSupply = 0; // amount of tokens already sold

    uint public price = 2000;
    uint public tokenSupplyLimit = 2000 * 10000 * (1 ether / 1 wei);

    bool public transferable = false;

    // Token manager has exclusive priveleges to call administrative
    // functions on this contract.
    address public tokenManager;

    // Gathered funds can be withdrawn only to escrow's address.
    address public escrow;

    // Crowdsale manager has exclusive priveleges to burn presale tokens.
    address public crowdsaleManager;

    // Migration registry address (for burn notifications)
    address public migrationRegistry;

    mapping (address => uint256) private balance;


    modifier onlyTokenManager()     { if(msg.sender != tokenManager) throw; _; }
    modifier onlyCrowdsaleManager() { if(msg.sender != crowdsaleManager) throw; _; }


    /*/
     *  Events
    /*/

    event LogBuy(address indexed owner, uint value);
    event LogBurn(address indexed owner, uint value);
    event LogPhaseSwitch(Phase newPhase);
    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);


    /*/
     *  Public functions
    /*/

    function() payable {
        buyTokens(msg.sender);
    }

    /// @dev Lets buy you some tokens.
    function buyTokens(address _buyer) public payable {
        // Available only if presale is running.
        if(currentPhase != Phase.Running) throw;

        if(msg.value <= 0) throw;
        uint newTokens = msg.value * price;
        if (totalSupply + newTokens > tokenSupplyLimit) throw;
        balance[_buyer] += newTokens;
        totalSupply += newTokens;
        LogBuy(_buyer, newTokens);
    }


    /// @dev Returns number of tokens owned by given address.
    /// @param _owner Address of token owner.
    function burnTokens(address _owner) public
        onlyCrowdsaleManager
    {
        // Available only during migration phase
        if(currentPhase != Phase.Migrating) throw;

        uint tokens = balance[_owner];
        if(tokens == 0) throw;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify migration registry about the burn operation
        // This external call happens before state updates
        if(migrationRegistry != 0x0) {
            migrationRegistry.call(bytes4(keccak256("recordBurn(address,uint256)")), _owner, tokens);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balance[_owner] = 0;
        totalSupply -= tokens;
        LogBurn(_owner, tokens);

        // Automatically switch phase when migration is done.
        if(totalSupply == 0) {
            currentPhase = Phase.Migrated;
            LogPhaseSwitch(Phase.Migrated);
        }
    }


    /// @dev Returns number of tokens owned by given address.
    /// @param _owner Address of token owner.
    function balanceOf(address _owner) constant returns (uint256) {
        return balance[_owner];
    }


    /*/
     *  Administrative functions
    /*/

    function setPresalePhase(Phase _nextPhase) public
        onlyTokenManager
    {
        bool canSwitchPhase
            =  (currentPhase == Phase.Created && _nextPhase == Phase.Running)
            || (currentPhase == Phase.Running && _nextPhase == Phase.Paused)
                // switch to migration phase only if crowdsale manager is set
            || ((currentPhase == Phase.Running || currentPhase == Phase.Paused)
                && _nextPhase == Phase.Migrating
                && crowdsaleManager != 0x0)
            || (currentPhase == Phase.Paused && _nextPhase == Phase.Running)
                // switch to migrated only if everyting is migrated
            || (currentPhase == Phase.Migrating && _nextPhase == Phase.Migrated
                && totalSupply == 0);

        if(!canSwitchPhase) throw;
        currentPhase = _nextPhase;
        LogPhaseSwitch(_nextPhase);
    }


    function withdrawEther() public
        onlyTokenManager
    {
        // Available at any phase.
        if(this.balance > 0) {
            if(!escrow.send(this.balance)) throw;
        }
    }


    function setCrowdsaleManager(address _mgr) public
        onlyTokenManager
    {
        // You can't change crowdsale contract when migration is in progress.
        if(currentPhase == Phase.Migrating) throw;
        crowdsaleManager = _mgr;
    }
    
    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (!transferable) throw;
        if (balance[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balance[_to] + _value < balance[_to]) throw; // Check for overflows
        balance[msg.sender] -= _value;                     // Subtract from the sender
        balance[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }
    
    function setTransferable(bool _value) public
        onlyTokenManager
    {
        transferable = _value;
    }
    
    function setPrice(uint256 _price) public
        onlyTokenManager
    {
        if(currentPhase != Phase.Paused) throw;
        if(_price <= 0) throw;

        price = _price;
    }

    function setTokenSupplyLimit(uint256 _value) public
        onlyTokenManager
    {
        if(currentPhase != Phase.Paused) throw;
        if(_value <= 0) throw;

        uint _tokenSupplyLimit;
        _tokenSupplyLimit = _value * (1 ether / 1 wei);

        if(totalSupply > _tokenSupplyLimit) throw;

        tokenSupplyLimit = _tokenSupplyLimit;
    }
}