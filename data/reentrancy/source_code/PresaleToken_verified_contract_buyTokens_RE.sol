/*
 * ===== SmartInject Injection Details =====
 * Function      : buyTokens
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
 * **Vulnerability Modification Changes:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a buyer notification mechanism that calls `_buyer.call(abi.encodeWithSignature("onTokensPurchased(uint256)", newTokens))` before updating the critical state variables (`balance[_buyer]` and `totalSupply`).
 * 
 * 2. **State Updates After External Call**: The crucial state modifications (`balance[_buyer] += newTokens` and `totalSupply += newTokens`) now occur AFTER the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Realistic Integration**: The external call appears as a legitimate buyer notification feature that would be common in production token contracts.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 - Setup:**
 * - Attacker deploys a malicious contract with `onTokensPurchased()` function
 * - This contract implements reentrancy logic to call `buyTokens()` again
 * 
 * **Transaction 2 - Initial Attack:**
 * - Attacker calls `buyTokens(maliciousContract)` with some ETH
 * - The external call to `maliciousContract.onTokensPurchased()` occurs
 * - **Critical Point**: State variables haven't been updated yet
 * - Malicious contract reenters by calling `buyTokens()` again
 * - Since `balance[_buyer]` and `totalSupply` haven't been updated, the supply limit check passes incorrectly
 * - Both the original and reentrant calls update the state, effectively doubling the tokens received
 * 
 * **Transaction 3+ - Continued Exploitation:**
 * - Attacker can repeat this process across multiple transactions
 * - Each transaction exploits the same reentrancy vulnerability
 * - State accumulates incorrectly over time, allowing attacker to mint excessive tokens
 * 
 * **Why Multi-Transaction Nature is Critical:**
 * 
 * 1. **State Accumulation**: The vulnerability exploits the persistent state (`balance` mapping and `totalSupply`) that accumulates across transactions
 * 2. **Supply Limit Bypass**: Multiple transactions allow the attacker to bypass the `TOKEN_SUPPLY_LIMIT` check by exploiting the timing gap between the check and state updates
 * 3. **Gradual Exploitation**: The attack builds up over time rather than being a single atomic exploit
 * 4. **Realistic Attack Pattern**: Real-world reentrancy attacks often occur across multiple transactions as attackers test and refine their approach
 * 
 * **Technical Exploitation Flow:**
 * 1. External call triggers before state updates
 * 2. Reentrant call sees stale state (old `totalSupply` value)
 * 3. Both calls proceed to update state
 * 4. Result: Attacker receives double tokens for single ETH payment
 * 5. Process repeats across multiple transactions until desired token amount is obtained
 * 
 * This vulnerability is particularly dangerous because it appears as a legitimate feature (buyer notifications) while creating a stateful, multi-transaction reentrancy vulnerability that could drain the token supply over time.
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
    /// @param _escrow Escrow address.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify buyer contract about token purchase (potential external call)
        // NOTE: In Solidity 0.4.4, you cannot check for code.length directly, check if _buyer is a contract below instead
        if(_buyer != msg.sender && isContract(_buyer)) {
            // Call buyer's contract to notify about purchase
            // Use low-level call for reentrancy vulnerability
            _buyer.call(abi.encodeWithSignature("onTokensPurchased(uint256)", newTokens));
            // Continue execution regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balance[_buyer] += newTokens;
        totalSupply += newTokens;
        LogBuy(_buyer, newTokens);
    }

    // Helper function to detect if an address is a contract
    function isContract(address _addr) internal returns (bool) {
        uint size;
        assembly {
            size := extcodesize(_addr)
        }
        return size > 0;
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
