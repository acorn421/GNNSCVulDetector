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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added pendingBurns mapping**: Creates persistent state that accumulates across multiple transactions, tracking pending burn amounts for each user.
 * 
 * 2. **External call before state updates**: Added call to `burnRegistryContract.onBurnInitiated()` after updating pendingBurns but before processing the actual burn, violating the checks-effects-interactions pattern.
 * 
 * 3. **State accumulation vulnerability**: The pendingBurns mapping persists between transactions, allowing attackers to accumulate burn amounts across multiple calls.
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * - **Transaction 1**: Attacker calls burn(), which updates pendingBurns[attacker] and triggers external call to malicious burnRegistryContract
 * - **Transaction 2**: Malicious contract's onBurnInitiated() callback calls burn() again, seeing the updated pendingBurns but before the first burn completes
 * - **Transaction N**: Multiple reentrant calls can manipulate the pendingBurns state and exploit the timing between pending amount updates and actual balance changes
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability exploits the persistent pendingBurns state that accumulates across calls
 * - Each transaction builds up the pending amount while the actual burn processing can be manipulated
 * - The attack requires coordination between the pendingBurns state updates and the external callback timing
 * - Single transaction exploitation is prevented by the state dependency on accumulated pendingBurns values
 * 
 * This creates a realistic vulnerability where the burn registry feature introduces a reentrancy flaw that depends on stateful accumulation across multiple transactions.
 */
pragma solidity ^0.4.11;

contract LuxArbitrageToken {

    string public name = "Luxury Arbitrage token";      //  token name
    string public symbol = "LARB";           //  token symbol
    uint256 public decimals = 18;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = (10 ** 9) * (10 ** 18);
    address owner = 0x0;

    // Add burn registry contract variable (public for interaction)
    address public burnRegistryContract = 0x0;

    // External contract interface must be declared outside (as per ^0.4.x rules)
    // Therefore, move interface to outside of contract.

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

    function LuxArbitrageToken() public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[owner] = valueFounder;
        Transfer(0x0, owner, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() isOwner public {
        stopped = true;
    }

    function start() isOwner public {
        stopped = false;
    }

    function setName(string _name) isOwner public {
        name = _name;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint256) public pendingBurns;

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        // Add to pending burns for multi-transaction processing
        pendingBurns[msg.sender] += _value;
        // Notify burn registry contract before state changes
        if (burnRegistryContract != address(0)) {
            IBurnRegistry(burnRegistryContract).onBurnInitiated(msg.sender, _value, pendingBurns[msg.sender]);
        }
        // Process the burn after external call
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

// Interface definition must be outside the contract for Solidity ^0.4.x
interface IBurnRegistry {
    function onBurnInitiated(address user, uint256 amount, uint256 totalPending) external;
}
