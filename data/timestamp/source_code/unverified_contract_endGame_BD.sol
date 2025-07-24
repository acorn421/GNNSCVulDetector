/*
 * ===== SmartInject Injection Details =====
 * Function      : endGame
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
 * Introduced a timestamp dependence vulnerability by adding time-based bonus calculations that rely on precise block.timestamp values. The vulnerability allows miners to manipulate block timestamps to maximize bonuses for specific players. The bonus calculation uses block.timestamp % 60 to determine bonus tiers, making it vulnerable to timestamp manipulation within the 15-minute window that miners can adjust timestamps. This creates a stateful, multi-transaction vulnerability because: 1) The game must be started and players must accumulate holdTimes through multiple passHotPotato transactions, 2) The vulnerability only manifests when endGame is called with manipulated timestamps, 3) The bonus affects the stored holdTimes state which impacts future game winner calculations and withdrawals, 4) The manipulated timestamp is also stored for use in future game calculations, creating persistent effects across multiple games.
 */
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

    constructor()
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

        feesTaken = feesTaken.add(feeTake);

        game.stakes[msg.sender] = msg.value.sub(feeTake);
        game.totalStake = game.totalStake.add(msg.value.sub(feeTake));
        game.players = game.players.add(1);

        emit PlayerJoined(currentGameId, msg.sender, msg.value.sub(feeTake),
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

        emit GameStarted(currentGameId, game.hotPotatoOwner, game.gameStart);
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
        emit AddressHeldFor(currentGameId, msg.sender, game.holdTimes[msg.sender]);

        if (game.holdTimes[msg.sender] > game.holdTimes[game.maxTimeHolder]) {
            game.maxTimeHolder = msg.sender;
            emit NewMaxTimeHolder(currentGameId, game.maxTimeHolder);
        }

        game.hotPotatoReceiveTime = block.timestamp;

        emit HotPotatoPassed(currentGameId, receiver);
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
        emit AddressHeldFor(currentGameId, game.hotPotatoOwner, game.holdTimes[msg.sender]);

        if (game.holdTimes[game.hotPotatoOwner] > game.holdTimes[game.maxTimeHolder]) {
            game.maxTimeHolder = game.hotPotatoOwner;
            emit NewMaxTimeHolder(currentGameId, game.maxTimeHolder);
        }

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Vulnerable: Apply time-based bonus to maxTimeHolder based on game end timing
        // This creates a timestamp dependence vulnerability where miners can manipulate
        // the block timestamp to maximize bonuses for specific players
        uint gameEndTime = block.timestamp;
        uint gameLength = gameEndTime.sub(game.gameStart);
        
        // Bonus calculation based on precise timing - vulnerable to timestamp manipulation
        if (gameLength % 60 < 30) {
            // If game ends in first half of any minute, apply 10% bonus to maxTimeHolder
            uint bonusTime10 = game.holdTimes[game.maxTimeHolder].mul(10) / 100;
            game.holdTimes[game.maxTimeHolder] = game.holdTimes[game.maxTimeHolder].add(bonusTime10);
        } else if (gameLength % 60 >= 45) {
            // If game ends in last 15 seconds of any minute, apply 20% bonus
            uint bonusTime20 = game.holdTimes[game.maxTimeHolder].mul(20) / 100;
            game.holdTimes[game.maxTimeHolder] = game.holdTimes[game.maxTimeHolder].add(bonusTime20);
        }

        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        emit GameEnded(currentGameId);

        currentGameId = currentGameId.add(1);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Store the game end timestamp for the next game's bonus calculations
        games[currentGameId].blockCreated = block.number;
        games[currentGameId].gameStart = gameEndTime; // This will be overwritten in startGame, but used for interim calculations
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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

        emit PlayerWithdrew(msg.sender);
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
