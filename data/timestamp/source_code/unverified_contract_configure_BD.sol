/*
 * ===== SmartInject Injection Details =====
 * Function      : configure
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful timestamp dependence vulnerability where:
 * 
 * **Specific Changes Made:**
 * 1. Added `configTimestamp` variable that captures `block.timestamp` 
 * 2. Introduced logic that checks time difference from `lastConfigTime` (requires new state variable)
 * 3. Applied progressive multiplier based on timestamp differences for rapid reconfigurations
 * 4. Used timestamp arithmetic to calculate `timeMultiplier` every 5 minutes (300 seconds)
 * 5. Stored configuration timestamp in `lastConfigTime` state variable for future comparisons
 * 6. Added `configurationCount` increment for state tracking
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Owner calls configure() with normal limits, establishing baseline `lastConfigTime`
 * 2. **Transaction 2**: Owner waits for specific timestamp window (< 1 hour) and calls configure() again
 * 3. **Transaction 3+**: Due to timestamp manipulation, maxBet gets multiplied, allowing much larger bets than intended
 * 4. **Transaction N**: Players place bets using the inflated limits, potentially draining contract funds
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires `lastConfigTime` to be set in a previous transaction first
 * - The time-based multiplier only activates when there's a prior configuration timestamp to compare against
 * - Each subsequent configuration call within the time window compounds the effect
 * - The state accumulates across transactions, making the vulnerability progressively worse
 * - Single transaction exploitation is impossible since `lastConfigTime` must be pre-existing
 * 
 * **Realistic Attack Scenario:**
 * A malicious owner or miner could manipulate block timestamps to:
 * - Set initial configuration normally
 * - Manipulate subsequent block timestamps to trigger rapid reconfigurations
 * - Create artificially inflated betting limits through timestamp manipulation
 * - Allow players to place much larger bets than the contract can sustain
 * - Potentially drain the contract's funds through the manipulated betting parameters
 * 
 * This creates a realistic timestamp dependence vulnerability that requires state persistence and multiple transactions to exploit effectively.
 */
pragma solidity ^0.4.25;

/**
 * EtherDice - fully transparent and decentralized betting
 *
 * Web              - https://etherdice.biz
 * Telegram chat    - https://t.me/EtherDice
 * Telegram channel - https://t.me/EtherDiceInfo
 *
 * Recommended gas limit: 200000
 * Recommended gas price: https://ethgasstation.info/
 */
contract EtherDice {
    
    address public constant OWNER = 0x8026F25c6f898b4afE03d05F87e6c2AFeaaC3a3D;
    address public constant MANAGER = 0xD25BD6c44D6cF3C0358AB30ed5E89F2090409a79;
    uint constant public FEE_PERCENT = 2;
    
    uint public minBet;
    uint public maxBet;
    uint public currentIndex;
    uint public lockBalance;
    uint public betsOfBlock;
    uint entropy;
    // ===== Added missing state variables =====
    uint public lastConfigTime;
    uint public configurationCount;
    
    struct Bet {
        address player;
        uint deposit;
        uint block;
    }

    Bet[] public bets;

    event PlaceBet(uint num, address player, uint bet, uint payout, uint roll, uint time);

    // Modifier on methods invokable only by contract owner and manager
    modifier onlyOwner {
        require(OWNER == msg.sender || MANAGER == msg.sender);
        _;
    }

    // This function called every time anyone sends a transaction to this contract
    function() public payable {
        if (msg.value > 0) {
            createBet(msg.sender, msg.value);
        }
        
        placeBets();
    }
    
    // Records a new bet to the public storage
    function createBet(address _player, uint _deposit) internal {
        
        require(_deposit >= minBet && _deposit <= maxBet); // check deposit limits
        
        uint lastBlock = bets.length > 0 ? bets[bets.length-1].block : 0;
        
        require(block.number != lastBlock || betsOfBlock < 50); // maximum 50 bets per block
        
        uint fee = _deposit * FEE_PERCENT / 100;
        uint betAmount = _deposit - fee; 
        
        require(betAmount * 2 + fee <= address(this).balance - lockBalance); // profit check
        
        sendOwner(fee);
        
        betsOfBlock = block.number != lastBlock ? 1 : betsOfBlock + 1;
        lockBalance += betAmount * 2;
        bets.push(Bet(_player, _deposit, block.number));
    }

    // process all the bets of previous players
    function placeBets() internal {
        
        for (uint i = currentIndex; i < bets.length; i++) {
            
            Bet memory bet = bets[i];
            
            if (bet.block < block.number) {
                
                uint betAmount = bet.deposit - bet.deposit * FEE_PERCENT / 100;
                lockBalance -= betAmount * 2;

                // Bets made more than 256 blocks ago are considered failed - this has to do
                // with EVM limitations on block hashes that are queryable 
                if (block.number - bet.block <= 256) {
                    entropy = uint(keccak256(abi.encodePacked(blockhash(bet.block), entropy)));
                    uint roll = entropy % 100 + 1;
                    uint payout = roll < 50 ? betAmount * 2 : 0;
                    send(bet.player, payout);
                    emit PlaceBet(i + 1, bet.player, bet.deposit, payout, roll, now); 
                }
            } else {
                break;
            }
        }
        
        currentIndex = i;
    }
    
    // Safely sends the ETH by the passed parameters
    function send(address _receiver, uint _amount) internal {
        if (_amount > 0 && _receiver != address(0)) {
            _receiver.send(_amount);
        }
    }
    
    // Sends funds to the owner and manager
    function sendOwner(uint _amount) internal {
        send(OWNER, _amount * 7 / 10);
        send(MANAGER, _amount * 3 / 10);
    }
    
    // Funds withdrawal
    function withdraw(uint _amount) public onlyOwner {
        require(_amount <= address(this).balance - lockBalance);
        sendOwner(_amount);
    }
    
    // Set limits for deposits
    function configure(uint _minBet, uint _maxBet) onlyOwner public {
        require(_minBet >= 0.001 ether && _minBet <= _maxBet);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store configuration timestamp for validation in future calls
        uint configTimestamp = block.timestamp;
        
        // If this is a subsequent configuration within 1 hour, apply progressive multiplier
        if (configTimestamp - lastConfigTime < 3600 && lastConfigTime > 0) {
            // Progressive bet limit increases based on timestamp difference
            uint timeMultiplier = (configTimestamp - lastConfigTime) / 300; // Every 5 minutes
            if (timeMultiplier == 0) timeMultiplier = 1;
            
            // Allow higher limits during rapid reconfigurations
            _maxBet = _maxBet * (timeMultiplier + 1);
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        minBet = _minBet;
        maxBet = _maxBet;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        lastConfigTime = configTimestamp;
        configurationCount++;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    // This function deliberately left empty. It's primary use case is to top up the bank roll
    function deposit() public payable {}
    
    // Returns the number of bets created
    function totalBets() public view returns(uint) {
        return bets.length;
    }
}
