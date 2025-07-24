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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to IBurnNotifiable(_owner).onTokenBurn(tokens) before state updates. This creates a classic reentrancy vulnerability where:
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. **Transaction 1**: Attacker calls burnTokens() for a malicious contract address
 * 2. **During Callback**: The external call triggers onTokenBurn() on the attacker's contract
 * 3. **Reentrancy**: The attacker's contract calls burnTokens() again before the original state updates complete
 * 4. **Transaction 2**: State inconsistency allows multiple burns of the same tokens or manipulation of totalSupply
 * 5. **State Persistence**: The vulnerability persists across transactions because balance and totalSupply states are manipulated incorrectly
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to deploy a malicious contract that implements IBurnNotifiable
 * - The exploit needs multiple calls to burnTokens() to drain tokens or manipulate phase transitions
 * - State changes from previous incomplete burn operations enable subsequent exploits
 * - The automatic phase switching logic can be manipulated through accumulated state corruption across multiple transactions
 * 
 * **Realistic Business Context:**
 * The external callback mechanism appears legitimate for notifying token holders about burns during migration, making this a subtle but dangerous vulnerability that could realistically appear in production code.
 */
pragma solidity ^0.4.4;

// Interface for IBurnNotifiable, needed for callback in burnTokens
interface IBurnNotifiable {
    function onTokenBurn(uint tokens) external;
}

// ERC20 token interface is implemented only partially.
// Token transfer is prohibited due to spec (see PRESALE-SPEC.md),
// hence some functions are left undefined:
//  - transfer, transferFrom,
//  - approve, allowance.

contract PresaleToken {

    /// @dev Constructor
    /// @param _tokenManager Token manager address.
    function PresaleToken(address _tokenManager, address _escrow) public {
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

    modifier onlyTokenManager()     { if(msg.sender != tokenManager) revert(); _; }
    modifier onlyCrowdsaleManager() { if(msg.sender != crowdsaleManager) revert(); _; }

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
        if(currentPhase != Phase.Running) revert();

        if(msg.value == 0) revert();
        uint newTokens = msg.value * PRICE;
        if (totalSupply + newTokens > TOKEN_SUPPLY_LIMIT) revert();
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
        if(currentPhase != Phase.Migrating) revert();

        uint tokens = balance[_owner];
        if(tokens == 0) revert();
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external contract about burn (callback opportunity)
        if(isContract(_owner)) {
            IBurnNotifiable(_owner).onTokenBurn(tokens);
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

    // Helper function to check if an address is a contract
    function isContract(address _addr) private returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
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

        if(!canSwitchPhase) revert();
        currentPhase = _nextPhase;
        LogPhaseSwitch(_nextPhase);
    }

    function withdrawEther() public
        onlyTokenManager
    {
        // Available at any phase.
        if(this.balance > 0) {
            if(!escrow.send(this.balance)) revert();
        }
    }

    function setCrowdsaleManager(address _mgr) public
        onlyTokenManager
    {
        // You can't change crowdsale contract when migration is in progress.
        if(currentPhase == Phase.Migrating) revert();
        crowdsaleManager = _mgr;
    }
}
