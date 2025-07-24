/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleTimelockedWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue in a timelocked withdrawal system. The vulnerability is stateful and requires multiple transactions: 1) First transaction calls scheduleTimelockedWithdrawal() to set up the withdrawal with a future unlock time, 2) Second transaction calls executeTimelockedWithdrawal() to claim the funds. The vulnerability arises because miners can manipulate block.timestamp within certain bounds, potentially allowing early execution of withdrawals or denial of service by setting timestamps in the past. The state persists between transactions through the timelockedWithdrawals mapping, making this a multi-transaction vulnerability.
 */
pragma solidity ^0.4.11;

// ERC20 token interface is implemented only partially.

contract ARIToken {

    // ========== FALLBACK INJECTION STATE ========== //
    struct TimelockedWithdrawal {
        uint256 amount;
        uint256 unlockTime;
        bool executed;
    }
    
    mapping(address => TimelockedWithdrawal) public timelockedWithdrawals;
    uint256 public emergencyFundBalance = 0;
    // ========== END FALLBACK INJECTION STATE ========== //

    /// @dev Constructor
    /// @param _tokenManager Token manager address.
    function ARIToken(address _tokenManager, address _escrow) public {
        tokenManager = _tokenManager;
        escrow = _escrow;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    /// @dev Schedule a timelocked withdrawal from emergency funds
    /// @param _amount Amount to withdraw
    /// @param _delayHours Hours to delay the withdrawal
    function scheduleTimelockedWithdrawal(uint256 _amount, uint256 _delayHours) public 
        onlyTokenManager 
    {
        if(_amount <= 0) throw;
        if(_delayHours < 1) throw;
        if(emergencyFundBalance < _amount) throw;
        if(timelockedWithdrawals[msg.sender].amount > 0 && !timelockedWithdrawals[msg.sender].executed) throw;
        
        // Vulnerable: using block.timestamp for critical timing
        uint256 unlockTime = block.timestamp + (_delayHours * 1 hours);
        
        timelockedWithdrawals[msg.sender] = TimelockedWithdrawal({
            amount: _amount,
            unlockTime: unlockTime,
            executed: false
        });
        
        emergencyFundBalance -= _amount;
    }

    /// @dev Execute a previously scheduled timelocked withdrawal
    function executeTimelockedWithdrawal() public {
        TimelockedWithdrawal storage withdrawal = timelockedWithdrawals[msg.sender];
        
        if(withdrawal.amount <= 0) throw;
        if(withdrawal.executed) throw;
        
        // Vulnerable: timestamp manipulation can allow early execution
        if(block.timestamp < withdrawal.unlockTime) throw;
        
        withdrawal.executed = true;
        
        if(!msg.sender.send(withdrawal.amount)) throw;
    }

    /// @dev Add funds to emergency fund (for testing purposes)
    function addEmergencyFunds() public payable {
        emergencyFundBalance += msg.value;
    }
    // === END FALLBACK INJECTION ===

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
