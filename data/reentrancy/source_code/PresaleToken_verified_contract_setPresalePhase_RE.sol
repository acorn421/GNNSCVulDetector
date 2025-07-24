/*
 * ===== SmartInject Injection Details =====
 * Function      : setPresalePhase
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Update**: Added a call to `crowdsaleManager.call()` before updating `currentPhase`, violating the Checks-Effects-Interactions pattern.
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker deploys malicious contract and calls `setCrowdsaleManager()` to set it as the crowdsaleManager
 *    - **Transaction 2**: Token manager calls `setPresalePhase()` which triggers the external call to the malicious crowdsaleManager
 *    - **During Reentrancy**: The malicious contract can call back into `setPresalePhase()` or other functions while `currentPhase` is still in its old state, allowing unauthorized phase transitions
 * 
 * 3. **State Persistence Requirement**: The vulnerability requires the malicious contract to be set as crowdsaleManager in a previous transaction, making it stateful and multi-transaction dependent.
 * 
 * 4. **Exploitation Scenarios**:
 *    - Attacker can cause double phase transitions by reentering during the external call
 *    - Can manipulate the presale to skip validation checks by calling setPresalePhase recursively
 *    - Can exploit the inconsistent state where external systems think the phase changed but internal state hasn't updated yet
 * 
 * 5. **Why Multi-Transaction**: The vulnerability cannot be exploited in a single transaction because:
 *    - The attacker must first become the crowdsaleManager (Transaction 1)
 *    - Then wait for the tokenManager to change phases (Transaction 2)
 *    - Only then can the reentrancy attack execute during the external call
 * 
 * The vulnerability is realistic as it mimics real-world patterns where contracts notify external systems about state changes, and the failure handling allows the function to proceed even if the notification fails, making it subtle and hard to detect.
 */
pragma solidity ^0.4.4;


// ERC20 token interface is implemented only partially.
// Token transfer is prohibited due to spec (see PRESALE-SPEC.md),
// hence some functions are left undefined:
//  - transfer, transferFrom,
//  - approve, allowance.

contract PresaleToken {

    /// @dev Constructor
    /// @param _tokenManager Token manager address.
    function PresaleToken(address _tokenManager, address _escrow) {
        tokenManager = _tokenManager;
        escrow = _escrow;
    }


    /*/
     *  Constants
    /*/

    string public constant name = "SONM Presale Token";
    string public constant symbol = "SPT";
    uint   public constant decimals = 18;

    uint public constant PRICE = 606; // 606 SPT per Ether

    //  price
    // Cup is 10 000 ETH
    // 1 eth = 606 presale tokens
    // ETH price ~50$ for 28.03.2017
    // Cup in $ is ~ 500 000$

    uint public constant TOKEN_SUPPLY_LIMIT = 606 * 10000 * (1 ether / 1 wei);



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

        if(msg.value == 0) throw;
        uint newTokens = msg.value * PRICE;
        if (totalSupply + newTokens > TOKEN_SUPPLY_LIMIT) throw;
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify crowdsale manager about phase change before updating state
        if(crowdsaleManager != 0x0) {
            // External call to crowdsaleManager before state update - vulnerable to reentrancy
            bool success = crowdsaleManager.call(bytes4(keccak256("onPhaseChange(uint8)")), uint8(_nextPhase));
            if(!success) {
                // If notification fails, still proceed with phase change
                // but log the failure for debugging
                LogPhaseSwitch(Phase.Paused); // Temporary log for debugging
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
}