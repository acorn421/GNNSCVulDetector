/*
 * ===== SmartInject Injection Details =====
 * Function      : distributeSMILE
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful timestamp dependence vulnerability through time-based bonus calculations. The vulnerability involves:
 * 
 * 1. **State Variables Added**: `lastDistributionTime` and `totalDistributions` to track distribution history
 * 2. **Time-Based Bonus System**: Added `calculateTimeBonus()` function that uses `block.timestamp` to determine distribution multipliers
 * 3. **Vulnerable Logic**: Bonus calculations depend on time gaps between distributions, making the contract susceptible to timestamp manipulation
 * 
 * **Multi-Transaction Exploitation:**
 * The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup)**: Attacker calls `distributeSMILE()` to establish initial `lastDistributionTime` state
 * **Transaction 2+ (Exploitation)**: Attacker (if they can influence block timestamps as a miner) or waits for natural timestamp variations to maximize bonus calculations
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Dependency**: The bonus calculation relies on comparing current `block.timestamp` with stored `lastDistributionTime` from previous calls
 * 2. **Accumulated Effect**: Each distribution updates the timestamp state, affecting future bonus calculations
 * 3. **Time Gap Exploitation**: The vulnerability only manifests when there are time gaps between distributions, requiring separate transactions
 * 
 * **Exploitation Scenarios:**
 * - **Miner Manipulation**: Miners can manipulate block timestamps (±15 seconds) to maximize bonus rates across multiple distribution calls
 * - **Strategic Timing**: Attackers can time distributions to fall into higher bonus tiers by waiting specific time periods
 * - **MEV Opportunities**: Front-runners could manipulate transaction ordering around timestamp boundaries to maximize received tokens
 * 
 * The vulnerability is realistic as time-based incentives are common in distribution contracts, but the reliance on `block.timestamp` for financial calculations creates manipulation opportunities that compound across multiple transactions.
 */
pragma solidity ^0.4.24;

/**
 * @title SMILE Token
 * @author Alex Papageorgiou - <alex.ppg@protonmail.com>
 * @notice The Smile Token token & airdrop contract which conforms to EIP-20 & partially ERC-223
 */
contract SMILE {

    /**
     * Constant EIP-20 / ERC-223 variables & getters
     */

    string constant public name = "Smile Token";
    string constant public symbol = "SMILE";
    uint256 constant public decimals = 18;
    uint256 constant public totalSupply = 100000000 * (10 ** decimals);

    /**
     * A variable to store the contract creator
     */

    address public creator;

    /**
     * A variable to declare whether distribution is on-going
     */

    bool public distributionFinished = false;

    /**
     * Classic EIP-20 / ERC-223 mappings and getters
     */

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /**
     *      EIP-20 Events. As the ERC-223 Transfer overlaps with EIP-20,
     *      observers are unable to track both. In order to be compatible,
     *      the ERC-223 Event spec is not integrated.
     */

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Mint(address indexed to, uint value);

    /**
     *      Ensures that the caller is the owner of the
     *      contract and that the address to withdraw from
     *      is not the contract itself.
     */

    modifier canWithdraw(address _tokenAddress) {
        assert(msg.sender == creator && _tokenAddress != address(this));
        _;
    }

    /**
     *      Ensures that the caller is the owner of the
     *      contract and that the distribution is still
     *      in effect.
     */

    modifier canDistribute() {
        assert(msg.sender == creator && !distributionFinished);
        _;
    }

    /**
     * Contract constructor which assigns total supply to caller & assigns caller as creator
     */

    constructor() public {
        creator = msg.sender;
        balanceOf[msg.sender] = totalSupply;
        emit Mint(msg.sender, totalSupply);
    }

    /**
     * Partial SafeMath library import of safe substraction
     * @param _a Minuend: The number to substract from
     * @param _b Subtrahend: The number that is to be subtracted
     */

    function safeSub(uint256 _a, uint256 _b) internal pure returns (uint256 c) {
        assert((c = _a - _b) <= _a);
    }

    /**
     * Partial SafeMath library import of safe multiplication
     * @param _a Multiplicand: The number to multiply
     * @param _b Multiplier: The number to multiply by
     */

    function safeMul(uint256 _a, uint256 _b) internal pure returns (uint256 c) {
        // Automatic failure on division by zero
        assert((c = _a * _b) / _a == _b);
    }

    /**
     * EIP-20 Transfer implementation
     * @param _to The address to send tokens to
     * @param _value The amount of tokens to send
     */

    function transfer(address _to, uint256 _value) public returns (bool) {
        // Prevent accidental transfers to the default 0x0 address
        assert(_to != 0x0);
        bytes memory empty;
        if (isContract(_to)) {
            return transferToContract(_to, _value, empty);
        } else {
            return transferToAddress(_to, _value);
        }
    }

    /**
     * ERC-223 Transfer implementation
     * @param _to The address to send tokens to
     * @param _value The amount of tokens to send
     * @param _data Any accompanying data for contract transfers
     */

    function transfer(address _to, uint256 _value, bytes _data) public returns (bool) {
        // Prevent accidental transfers to the default 0x0 address
        assert(_to != 0x0);
        if (isContract(_to)) {
            return transferToContract(_to, _value, _data);
        } else {
            return transferToAddress(_to, _value);
        }
    }

    /**
     * EIP-20 Transfer From implementation
     * @param _from The address to transfer tokens from
     * @param _to The address to transfer tokens to
     * @param _value The amount of tokens to transfer
     */

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        allowance[_from][_to] = safeSub(allowance[_from][_to], _value);
        balanceOf[_from] = safeSub(balanceOf[_from], _value);
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    /**
     * EIP-20 Approve implementation (Susceptible to Race Condition, mitigation optional)
     * @param _spender The address to delegate spending rights to
     * @param _value The amount of tokens to delegate
     */

    function approve(address _spender, uint256 _value) public returns (bool) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    /**
     * ERC-223 Transfer to Contract implementation
     * @param _to The contract address to send tokens to
     * @param _value The amount of tokens to send
     * @param _data Any accompanying data to relay to the contract
     */

    function transferToContract(address _to, uint256 _value, bytes _data) private returns (bool) {
        balanceOf[msg.sender] = safeSub(balanceOf[msg.sender], _value);
        balanceOf[_to] += _value;
        SMILE interfaceProvider = SMILE(_to);
        interfaceProvider.tokenFallback(msg.sender, _value, _data);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    /**
     * ERC-223 Token Fallback interface implementation
     * @param _from The address that initiated the transfer
     * @param _value The amount of tokens transferred
     * @param _data Any accompanying data to relay to the contract
     */

    function tokenFallback(address _from, uint256 _value, bytes _data) public {}

    /**
     * 
     *      Partial ERC-223 Transfer to Address implementation.
     *      The bytes parameter is intentioanlly dropped as it
     *      is not utilized.
     *
     * @param _to The address to send tokens to
     * @param _value The amount of tokens to send
     */

    function transferToAddress(address _to, uint256 _value) private returns (bool) {
        balanceOf[msg.sender] = safeSub(balanceOf[msg.sender], _value);
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    /**
     * ERC-223 Contract check implementation
     * @param _addr The address to check contract existance in
     */

    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        // NE is more gas efficient than GT
        return (length != 0);
    }

    /**
     * Implementation of a multi-user distribution function
     * @param _addresses The array of addresses to transfer to
     * @param _value The amount of tokens to transfer to each
     */

    function distributeSMILE(address[] _addresses, uint256 _value) canDistribute external {
         // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
         // Time-based bonus calculation using block timestamp
         uint256 timeBonus = calculateTimeBonus();
         uint256 finalValue = safeMul(_value, timeBonus) / 100;
         
         for (uint256 i = 0; i < _addresses.length; i++) {
             balanceOf[_addresses[i]] += finalValue;
             emit Transfer(msg.sender, _addresses[i], finalValue);
         }
         
         // Update distribution state with current timestamp
         lastDistributionTime = block.timestamp;
         totalDistributions++;
         
         // Can be removed in one call instead of each time within the loop
         balanceOf[msg.sender] = safeSub(balanceOf[msg.sender], safeMul(finalValue, _addresses.length));
    }
    
    // State variables for timestamp tracking (would be added to contract)
    uint256 public lastDistributionTime;
    uint256 public totalDistributions;
    
    function calculateTimeBonus() internal view returns (uint256) {
        if (lastDistributionTime == 0) {
            return 100; // Base rate for first distribution
        }
        
        uint256 timeSinceLastDistribution = block.timestamp - lastDistributionTime;
        
        // Vulnerable logic: Bonus increases based on time gaps
        // Short time gaps (< 1 hour) get reduced rates
        if (timeSinceLastDistribution < 3600) {
            return 50; // 50% of base value
        }
        // Medium gaps (1-24 hours) get normal rates  
        else if (timeSinceLastDistribution < 86400) {
            return 100; // 100% of base value
        }
        // Long gaps (> 24 hours) get bonus rates
        else {
            // Vulnerable: Uses block.timestamp for bonus calculation
            uint256 daysSince = timeSinceLastDistribution / 86400;
            uint256 bonus = 100 + (daysSince * 10); // 10% bonus per day
            return bonus > 200 ? 200 : bonus; // Cap at 200%
        }
    }
         // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

    /**
     * Implementation to retrieve accidentally sent EIP-20 compliant tokens
     * @param _token The contract address of the EIP-20 compliant token
     */

    function retrieveERC(address _token) external canWithdraw(_token) {
        SMILE interfaceProvider = SMILE(_token);
        // By default, the whole balance of the contract is sent to the caller
        interfaceProvider.transfer(msg.sender, interfaceProvider.balanceOf(address(this)));
    }

    /**
     *      Absence of payable modifier is intentional as
     *      it causes accidental Ether transfers to throw.
     */

    function() public {}
}