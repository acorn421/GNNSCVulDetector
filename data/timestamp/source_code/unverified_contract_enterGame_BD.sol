/*
 * ===== SmartInject Injection Details =====
 * Function      : enterGame
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a multi-transaction timestamp dependence that allows miners and sophisticated attackers to manipulate game entry conditions through strategic timing across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Dynamic Fee Calculation**: Added time-based fee discounts using `block.timestamp` and `game.blockCreated` to create early-joiner advantages
 * 2. **Timestamp-based Priority System**: Implemented a "priority" calculation using `block.timestamp` combined with `keccak256` hashing that appears random but is actually predictable
 * 3. **State Persistence**: The calculated priority is stored in `game.holdTimes[msg.sender]` (reusing existing mapping) to affect future game mechanics
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * 1. **Miner Manipulation**: A miner can observe pending `enterGame` transactions and manipulate `block.timestamp` within the 15-second tolerance to:
 *    - Ensure their transaction gets maximum fee discounts
 *    - Manipulate the priority calculation to get advantageous player ordering
 *    - Affect multiple players' joining conditions across sequential transactions
 * 
 * 2. **Time-based Arbitrage**: An attacker can:
 *    - Monitor game creation times and calculate optimal joining windows
 *    - Submit multiple transactions at strategic timestamps to maximize fee savings
 *    - Exploit the priority system by timing entries when timestamp-based calculations favor them
 * 
 * 3. **Accumulated State Exploitation**: Since priorities are stored in state, an attacker can:
 *    - Join multiple games with timestamp-manipulated priorities
 *    - Use the predictable nature of `block.timestamp` to gain consistent advantages
 *    - Exploit the cumulative effect of timestamp-based advantages across games
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * - **State Accumulation**: The vulnerability requires game state to be established first (game.blockCreated), then exploited in subsequent transactions
 * - **Sequential Dependency**: Players must join in sequence, allowing attackers to observe and react to previous transactions
 * - **Timing Windows**: The fee discount system creates time-based windows that can only be exploited through carefully timed separate transactions
 * - **Priority Persistence**: The stored priority values affect future game mechanics, requiring the vulnerability to span multiple transaction contexts
 * 
 * This creates a realistic vulnerability where the timestamp dependence isn't immediately obvious but provides systematic advantages to miners and sophisticated attackers who can manipulate or predict block timestamps across multiple transactions.
 */
pragma solidity ^0.4.19;

pragma solidity ^0.4.19;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
    // precision of division
    uint constant private DIV_PRECISION = 3;

    /**
    * @dev Multiplies two numbers, throws on overflow.
    */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    /**
    * @dev Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
    */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    /**
    * @dev Adds two numbers, throws on overflow.
    */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }

    function percent(uint numerator, uint denominator, uint precision)
    internal
    pure
    returns (uint quotient) {
        // caution, check safe-to-multiply here
        uint _numerator = mul(numerator, 10 ** (precision + 1));

        // with rounding of last digit
        uint _quotient = add((_numerator / denominator), 5) / 10;
        return (_quotient);
    }
}

contract HotPotato {
    using SafeMath for uint;

    event GameStarted(uint indexed gameId, address hotPotatoOwner, uint gameStart);
    event GameEnded(uint indexed gameId);
    event HotPotatoPassed(uint indexed gameId, address receiver);
    event PlayerJoined(uint indexed gameId, address player, uint stake, uint totalStake, uint players);
    event PlayerWithdrew(address indexed player);
    event NewMaxTimeHolder(uint indexed gameId, address maxTimeHolder);
    event AddressHeldFor(uint indexed gameId, address player, uint timeHeld);

    struct Game {
        // whether the game is running and the timer has started
        bool running;

        // game has completed it's whole run
        bool finished;

        // who owns the hot potato in the game
        address hotPotatoOwner;

        // the unix timestamp of when the game when started
        uint gameStart;

        // players to their stakes (a stake >0 indicates the address is playing)
        mapping(address => uint) stakes;

        // the total amount of Ether staked on the game
        uint totalStake;

        // players in the game
        uint players;

        // whether an address has withdrawed there stake or not
        mapping(address => bool) withdrawals;

        // the time the addresses held the potato for in seconds
        mapping(address => uint) holdTimes;

        // the block the game was created on (i.e. when players could join it)
        uint blockCreated;

        // the time the hot potato was received last
        uint hotPotatoReceiveTime;

        // the address which has held the hot potato the longest so far
        address maxTimeHolder;
    }

    // fees taken per stake as a percent of 1 ether
    uint constant private FEE_TAKE = 0.02 ether;

    // the degree of precision for division
    uint constant private DIV_DEGREE_PRECISION = 3;

    // the minimum amount of ether to enter the game
    uint constant public MIN_STAKE = 0.01 ether;

    // the minimum amount of players to start a game
    uint constant public MIN_PLAYERS = 3;

    // duration of a game in seconds (10 mins)
    uint constant public GAME_DURATION = 600;

    // who owns/publishes the contract
    address private contractOwner;

    // the amount of fees collected
    uint public feesTaken;

    // the current game id
    uint public currentGameId;

    // game ids to games
    mapping(uint => Game) public games;

    modifier gameRunning(uint gameId) {
        require(games[gameId].running);

        _;
    }

    modifier gameStopped(uint gameId) {
        require(!games[gameId].running);

        _;
    }

    modifier gameFinished(uint gameId) {
        require(games[gameId].finished);

        _;
    }

    modifier hasValue(uint amount) {
        require(msg.value >= amount);

        _;
    }

    modifier notInGame(uint gameId, address player) {
        require(games[gameId].stakes[player] == 0);

        _;
    }

    modifier inGame(uint gameId, address player) {
        require(games[gameId].stakes[player] > 0);

        _;
    }

    modifier enoughPlayers(uint gameId) {
        require(games[gameId].players >= MIN_PLAYERS);

        _;
    }

    modifier hasHotPotato(uint gameId, address player) {
        require(games[gameId].hotPotatoOwner == player);

        _;
    }

    modifier notLost(uint gameId, address player) {
        require(games[gameId].hotPotatoOwner != player && games[gameId].maxTimeHolder != player);

        _;
    }

    modifier gameTerminable(uint gameId) {
        require(block.timestamp.sub(games[gameId].gameStart) >= GAME_DURATION);

        _;
    }

    modifier notWithdrew(uint gameId) {
        require(!games[gameId].withdrawals[msg.sender]);

        _;
    }

    modifier onlyContractOwner() {
        require(msg.sender == contractOwner);

        _;
    }

    function HotPotato()
    public
    payable {
        contractOwner = msg.sender;
        games[0].blockCreated = block.number;
    }

    function enterGame()
    public
    payable
    gameStopped(currentGameId)
    hasValue(MIN_STAKE)
    notInGame(currentGameId, msg.sender) {
        Game storage game = games[currentGameId];

        uint feeTake = msg.value.mul(FEE_TAKE) / (1 ether);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Vulnerable: Dynamic fee adjustment based on block timestamp
        // Early joiners get discounted fees based on time since game creation
        uint timeSinceCreation = block.timestamp - (game.blockCreated * 15); // Approximate block time
        uint feeDiscount = 0;
        
        if (timeSinceCreation < 300) { // First 5 minutes
            feeDiscount = feeTake.mul(50) / 100; // 50% discount
        } else if (timeSinceCreation < 600) { // Next 5 minutes
            feeDiscount = feeTake.mul(25) / 100; // 25% discount
        }
        
        feeTake = feeTake.sub(feeDiscount);
        
        // Store timestamp-based priority for later use in game mechanics
        game.stakes[msg.sender] = msg.value.sub(feeTake);
        
        // Vulnerable: Use block.timestamp for deterministic "random" player ordering
        // This creates predictable advantages that miners can manipulate
        uint playerPriority = uint(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 1000;
        
        // Store the timestamp-based priority in holdTimes temporarily (reused field)
        game.holdTimes[msg.sender] = block.timestamp + playerPriority;

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        feesTaken = feesTaken.add(feeTake);
        game.totalStake = game.totalStake.add(msg.value.sub(feeTake));
        game.players = game.players.add(1);

        PlayerJoined(currentGameId, msg.sender, msg.value.sub(feeTake),
            game.totalStake, game.players);
    }

    function startGame(address receiver)
    public
    payable
    gameStopped(currentGameId)
    inGame(currentGameId, msg.sender)
    inGame(currentGameId, receiver)
    enoughPlayers(currentGameId) {
        Game storage game = games[currentGameId];

        game.running = true;
        game.hotPotatoOwner = receiver;
        game.hotPotatoReceiveTime = block.timestamp;
        game.gameStart = block.timestamp;
        game.maxTimeHolder = receiver;

        GameStarted(currentGameId, game.hotPotatoOwner, game.gameStart);
    }

    function passHotPotato(address receiver)
    public
    payable
    gameRunning(currentGameId)
    hasHotPotato(currentGameId, msg.sender)
    inGame(currentGameId, receiver) {
        Game storage game = games[currentGameId];

        game.hotPotatoOwner = receiver;

        uint timeHeld = block.timestamp.sub(game.hotPotatoReceiveTime);
        game.holdTimes[msg.sender] = game.holdTimes[msg.sender].add(timeHeld);
        AddressHeldFor(currentGameId, msg.sender, game.holdTimes[msg.sender]);

        if (game.holdTimes[msg.sender] > game.holdTimes[game.maxTimeHolder]) {
            game.maxTimeHolder = msg.sender;
            NewMaxTimeHolder(currentGameId, game.maxTimeHolder);
        }

        game.hotPotatoReceiveTime = block.timestamp;

        HotPotatoPassed(currentGameId, receiver);
    }

    function endGame()
    public
    payable
    gameRunning(currentGameId)
    inGame(currentGameId, msg.sender)
    gameTerminable(currentGameId) {
        Game storage game = games[currentGameId];

        game.running = false;
        game.finished = true;

        uint timeHeld = block.timestamp.sub(game.hotPotatoReceiveTime);
        game.holdTimes[game.hotPotatoOwner] = game.holdTimes[game.hotPotatoOwner].add(timeHeld);
        AddressHeldFor(currentGameId, game.hotPotatoOwner, game.holdTimes[msg.sender]);

        if (game.holdTimes[game.hotPotatoOwner] > game.holdTimes[game.maxTimeHolder]) {
            game.maxTimeHolder = game.hotPotatoOwner;
            NewMaxTimeHolder(currentGameId, game.maxTimeHolder);
        }

        GameEnded(currentGameId);

        currentGameId = currentGameId.add(1);
        games[currentGameId].blockCreated = block.number;
    }

    function withdraw(uint gameId)
    public
    payable
    gameFinished(gameId)
    inGame(gameId, msg.sender)
    notLost(gameId, msg.sender)
    notWithdrew(gameId) {
        Game storage game = games[gameId];

        uint banishedStake = 0;

        if (game.hotPotatoOwner == game.maxTimeHolder) {
            banishedStake = game.stakes[game.hotPotatoOwner];
        } else {
            banishedStake = game.stakes[game.hotPotatoOwner].add(game.stakes[game.maxTimeHolder]);
        }

        uint collectiveStake = game.totalStake.sub(banishedStake);

        uint stake = game.stakes[msg.sender];

        uint percentageClaim = SafeMath.percent(stake, collectiveStake, DIV_DEGREE_PRECISION);

        uint claim = stake.add(banishedStake.mul(percentageClaim) / (10 ** DIV_DEGREE_PRECISION));

        game.withdrawals[msg.sender] = true;

        msg.sender.transfer(claim);

        PlayerWithdrew(msg.sender);
    }

    function withdrawFees()
    public
    payable
    onlyContractOwner {
        uint feesToTake = feesTaken;
        feesTaken = 0;
        contractOwner.transfer(feesToTake);
    }

    // GETTERS
    function getGame(uint gameId)
    public
    constant
    returns (bool, bool, address, uint, uint, uint, uint, address, uint) {
        Game storage game = games[gameId];
        return (
        game.running,
        game.finished,
        game.hotPotatoOwner,
        game.gameStart,
        game.totalStake,
        game.players,
        game.blockCreated,
        game.maxTimeHolder,
        currentGameId);
    }
}