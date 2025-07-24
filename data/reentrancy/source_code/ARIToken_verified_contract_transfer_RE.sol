/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **1. Specific Changes Made:**
 * - Added external call to recipient contract using `_to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value))`
 * - Placed the external call AFTER state changes (balance updates) but before event emission
 * - Added check for contract code existence before making the call
 * - Used low-level call that doesn't revert on failure to maintain original function behavior
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Initial Setup:**
 * - Attacker deploys malicious contract with `onTokenReceived` function
 * - Victim calls `transfer()` to send tokens to attacker's contract
 * - State changes occur: `balance[victim] -= _value` and `balance[attacker] += _value`
 * - External call triggers attacker's `onTokenReceived` callback
 * 
 * **Transaction 2 - Reentrancy Attack:**
 * - Inside `onTokenReceived`, attacker calls `transfer()` again
 * - The first transaction's state changes are already committed and persistent
 * - Attacker can now transfer tokens using the updated balance from Transaction 1
 * - This creates a chain of reentrant calls, each seeing persistent state from previous calls
 * 
 * **3. Why Multiple Transactions Are Required:**
 * 
 * **State Persistence Critical Factor:**
 * - The `balance` mapping changes persist between function calls
 * - Each reentrant call sees the updated balance state from previous calls
 * - The vulnerability exploits the accumulated state changes across multiple function invocations
 * 
 * **Multi-Transaction Dependency:**
 * - **Transaction 1**: Establishes initial state change and triggers callback
 * - **Transaction 2+**: Reentrant calls that exploit the persistent state modifications
 * - Each subsequent call can drain additional tokens because balance state persists
 * 
 * **Example Attack Flow:**
 * 1. Victim has 1000 tokens, calls `transfer(attacker, 100)`
 * 2. State updated: `balance[victim] = 900, balance[attacker] = 100`
 * 3. External call triggers `attacker.onTokenReceived(victim, 100)`
 * 4. Attacker's callback calls `transfer(attacker, 200)` - this is Transaction 2
 * 5. State check passes because `balance[victim] = 900` (persistent from Transaction 1)
 * 6. Additional 200 tokens transferred, total stolen = 300 tokens
 * 
 * **4. Realistic Attack Vector:**
 * - The vulnerability appears as a legitimate token receiver notification system
 * - Many real-world tokens implement similar callback mechanisms
 * - The flaw is subtle - state changes before external calls create the vulnerability window
 * - Attackers can create contracts that appear legitimate but contain malicious `onTokenReceived` implementations
 * 
 * **5. Multi-Transaction Exploitation Requirement Satisfied:**
 * - Cannot be exploited in a single atomic transaction
 * - Requires the persistent state changes from Transaction 1 to enable Transaction 2
 * - The attack effectiveness increases with each reentrant call due to accumulated state changes
 * - State persistence across transactions is the key enabler of the vulnerability
 */
pragma solidity ^0.4.11;

// ERC20 token interface is implemented only partially.

contract ARIToken {

    /// @dev Constructor
    /// @param _tokenManager Token manager address.
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

    mapping (address => uint256) private balance;

    modifier onlyTokenManager()     { if(msg.sender != tokenManager) revert(); _; }
    modifier onlyCrowdsaleManager() { if(msg.sender != crowdsaleManager) revert(); _; }

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

    function() public payable {
        buyTokens(msg.sender);
    }

    /// @dev Lets buy you some tokens.
    function buyTokens(address _buyer) public payable {
        // Available only if presale is running.
        if(currentPhase != Phase.Running) revert();

        if(msg.value <= 0) revert();
        uint newTokens = msg.value * price;
        if (totalSupply + newTokens > tokenSupplyLimit) revert();
        balance[_buyer] += newTokens;
        totalSupply += newTokens;
        emit LogBuy(_buyer, newTokens);
    }

    /// @dev Returns number of tokens owned by given address.
    /// @param _owner Address of token owner.
    function burnTokens(address _owner) public
        onlyCrowdsaleManager
    {
        // Available only during migration phase
        if(currentPhase != Phase.Migrating) revert();

        uint tokens = balance[_owner];
        if(tokens == 0) revert();
        balance[_owner] = 0;
        totalSupply -= tokens;
        emit LogBurn(_owner, tokens);

        // Automatically switch phase when migration is done.
        if(totalSupply == 0) {
            currentPhase = Phase.Migrated;
            emit LogPhaseSwitch(Phase.Migrated);
        }
    }

    /// @dev Returns number of tokens owned by given address.
    /// @param _owner Address of token owner.
    function balanceOf(address _owner) public constant returns (uint256) {
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

        if(!canSwitchPhase) revert();
        currentPhase = _nextPhase;
        emit LogPhaseSwitch(_nextPhase);
    }

    function withdrawEther() public
        onlyTokenManager
    {
        // Available at any phase.
        if(address(this).balance > 0) {
            if(!escrow.send(address(this).balance)) revert();
        }
    }

    function setCrowdsaleManager(address _mgr) public
        onlyTokenManager
    {
        // You can't change crowdsale contract when migration is in progress.
        if(currentPhase == Phase.Migrating) revert();
        crowdsaleManager = _mgr;
    }
    
    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (!transferable) revert();
        if (balance[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balance[_to] + _value < balance[_to]) revert(); // Check for overflows
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // State changes before external call - creates reentrancy window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balance[msg.sender] -= _value;                     // Subtract from the sender
        balance[_to] += _value;                            // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call to receiver contract after state changes
        // This allows the recipient to call back into this contract while balances are updated
        if (isContract(_to)) {
            // Call onTokenReceived if recipient is a contract
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue execution regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }
    
    function setTransferable(bool _value) public
        onlyTokenManager
    {
        transferable = _value;
    }
    
    function setPrice(uint256 _price) public
        onlyTokenManager
    {
        if(currentPhase != Phase.Paused) revert();
        if(_price <= 0) revert();

        price = _price;
    }

    function setTokenSupplyLimit(uint256 _value) public
        onlyTokenManager
    {
        if(currentPhase != Phase.Paused) revert();
        if(_value <= 0) revert();

        uint _tokenSupplyLimit;
        _tokenSupplyLimit = _value * (1 ether / 1 wei);

        if(totalSupply > _tokenSupplyLimit) revert();

        tokenSupplyLimit = _tokenSupplyLimit;
    }
    
    // Helper to detect contracts (pre-0.8 compatible)
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
