module.exports = {
    get: (req, res) => {
        res.send(`
        <!DOCTYPE html>
<html lang="fr">
    <head>
        <meta charset="utf-8">
        <title>Authentification</title>
    </head>
    <body>
        <h1>Authentification</h1>
        <form method="get" action="">
            <p>Donnez-moi votre argent</p>
            <label>Nom d'utilisateur</label> : <input type="email" name="Username" id="Username"/>
            <br/><br/>
            <label>Mot de passe</label> : <input type="text" name="Password" id="Password"/>
            <br/><br/>
            <button>Submit</button>
        </form>
    </body>
</html>
                `);
    }
};